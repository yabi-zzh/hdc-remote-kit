package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

const (
	forwardPaddingBytes = 8
	forwardContextBytes = 4
	forwardBufferBytes  = 64 * 1024
	forwardOutputBytes  = 4 * 1024
)

const (
	failForwardInvalidRequest = "[Fail] Forward request is invalid."
	failForwardUnsupported    = "[Fail] Forward type is not supported."
	failForwardSetup          = "[Fail] Forward setup failed."
	failForwardNoResult       = "[Fail] Forward setup did not return a result."
	failForwardTimeout        = "[Fail] Forward setup timed out."
)

// ForwardBridge 处理 forward 族：fport 时本服务为 slave，rport 时本服务为 master。
// 每个 forward session 维护 local/remote 端点、方向与 TCP 上下文；
// 端点支持 tcp 与 localabstract/localreserved/localfilesystem（域套接字族），设备侧 schema 由主 HDC 透传处理。
type ForwardBridge struct {
	ctx          context.Context
	codec        *protocol.Codec
	setupTimeout time.Duration
	openTarget   OpenTargetFunc
	write        FrameWriter
	logger       *slog.Logger

	mu              sync.Mutex
	bindings        map[uint32]*forwardBinding
	contexts        map[forwardContextKey]*forwardTCPContext
	reverseBindings map[uint32]*reverseBinding
	reverseConns    map[forwardContextKey]*reverseConn
	closed          bool
	closeWg         sync.WaitGroup
}

// NewForwardBridge 构造 forward 族桥接（fport 时本服务为 slave、rport 时为 master）；setupTimeout 控制建立阶段超时。
func NewForwardBridge(
	ctx context.Context,
	codec *protocol.Codec,
	setupTimeout time.Duration,
	openTarget OpenTargetFunc,
	write FrameWriter,
) *ForwardBridge {
	return &ForwardBridge{
		ctx: ctx, codec: codec, setupTimeout: setupTimeout,
		openTarget: openTarget, write: write,
		bindings:        make(map[uint32]*forwardBinding),
		contexts:        make(map[forwardContextKey]*forwardTCPContext),
		reverseBindings: make(map[uint32]*reverseBinding),
		reverseConns:    make(map[forwardContextKey]*reverseConn),
	}
}

// SetLogger 注入日志器用于诊断（可选，nil 时静默）。
func (b *ForwardBridge) SetLogger(logger *slog.Logger) {
	b.logger = logger
}

// debug 输出 rport 等链路的诊断信息，固定 Debug 级别，避免刷屏 Info 主日志。
func (b *ForwardBridge) debug(message string, args ...any) {
	if b.logger != nil {
		b.logger.Debug(message, args...)
	}
}

// Handle 按命令把 forward 族帧分派到 fport（本服务为 slave）或 rport（本服务为 master）上下文。
func (b *ForwardBridge) Handle(frame protocol.Frame) error {
	switch frame.CommandFlag {
	// fport：本服务为 slave 侧
	case protocol.CommandForwardCheck:
		return b.handleCheck(frame)
	case protocol.CommandForwardActiveSlave:
		return b.handleActiveSlave(frame)
	// rport：本服务为 master 侧
	case protocol.CommandForwardInit:
		return b.handleReverseInit(frame)
	case protocol.CommandForwardCheckResult:
		return b.handleReverseCheckResult(frame)
	case protocol.CommandForwardActiveMaster:
		return b.handleReverseActiveMaster(frame)
	// 数据/释放：按 contextID 归属分派到 fport 或 rport 上下文
	case protocol.CommandForwardData:
		return b.handleData(frame)
	case protocol.CommandForwardFreeContext:
		return b.handleFreeContext(frame)
	case protocol.CommandForwardList,
		protocol.CommandForwardRemove,
		protocol.CommandForwardSuccess:
		return b.reject(frame.ChannelID, failForwardUnsupported)
	default:
		return b.reject(frame.ChannelID, failForwardUnsupported)
	}
}

// CloseChannel 关闭指定 channel 上的全部 fport/rport 绑定、上下文与反向连接（收到 ChannelClose 时调用）。
func (b *ForwardBridge) CloseChannel(channelID uint32) {
	b.mu.Lock()
	binding := b.bindings[channelID]
	delete(b.bindings, channelID)
	contexts := b.takeContextsLocked(channelID)
	reverseBind := b.reverseBindings[channelID]
	delete(b.reverseBindings, channelID)
	reverses := b.takeReverseConnsLocked(channelID)
	b.mu.Unlock()

	for _, context := range contexts {
		context.close(false)
	}
	for _, reverse := range reverses {
		reverse.close(false)
	}
	if binding != nil {
		binding.close()
	}
	if reverseBind != nil {
		reverseBind.close()
	}
}

// Close 关闭 forward 桥：拆除所有 fport/rport 绑定、TCP 上下文与反向连接并等待 goroutine 退出。
func (b *ForwardBridge) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	bindings := make([]*forwardBinding, 0, len(b.bindings))
	for channelID, binding := range b.bindings {
		bindings = append(bindings, binding)
		delete(b.bindings, channelID)
	}
	contexts := make([]*forwardTCPContext, 0, len(b.contexts))
	for key, context := range b.contexts {
		contexts = append(contexts, context)
		delete(b.contexts, key)
	}
	reverseBindings := make([]*reverseBinding, 0, len(b.reverseBindings))
	for channelID, reverseBind := range b.reverseBindings {
		reverseBindings = append(reverseBindings, reverseBind)
		delete(b.reverseBindings, channelID)
	}
	reverses := make([]*reverseConn, 0, len(b.reverseConns))
	for key, reverse := range b.reverseConns {
		reverses = append(reverses, reverse)
		delete(b.reverseConns, key)
	}
	b.mu.Unlock()

	for _, context := range contexts {
		context.close(false)
	}
	for _, reverse := range reverses {
		reverse.close(false)
	}
	for _, binding := range bindings {
		binding.close()
	}
	for _, reverseBind := range reverseBindings {
		reverseBind.close()
	}
	b.closeWg.Wait()
}

func (b *ForwardBridge) handleCheck(frame protocol.Frame) error {
	contextID, endpoint, err := decodeForwardEndpoint(frame.Payload)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}

	port, err := allocateForwardPort()
	if err != nil {
		return b.reject(frame.ChannelID, failForwardSetup)
	}
	binding := &forwardBinding{
		owner:          b,
		channelID:      frame.ChannelID,
		checkContextID: contextID,
		remoteEndpoint: endpoint,
		localPort:      port,
		done:           make(chan struct{}),
	}

	b.mu.Lock()
	if b.closed || b.bindings[frame.ChannelID] != nil {
		b.mu.Unlock()
		return b.reject(frame.ChannelID, failForwardInvalidRequest)
	}
	b.bindings[frame.ChannelID] = binding
	b.closeWg.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.closeWg.Done()
		b.runBinding(binding)
	}()
	return nil
}

func (b *ForwardBridge) handleActiveSlave(frame protocol.Frame) error {
	contextID, endpoint, err := decodeForwardEndpoint(frame.Payload)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}

	b.mu.Lock()
	binding := b.bindings[frame.ChannelID]
	closed := b.closed
	b.mu.Unlock()
	if closed || binding == nil || binding.remoteEndpoint != endpoint || !binding.isReady() {
		return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardFreeContext, contextID, nil))
	}

	key := forwardContextKey{channelID: frame.ChannelID, contextID: contextID}
	context := &forwardTCPContext{owner: b, key: key, binding: binding}
	b.mu.Lock()
	if b.closed || b.contexts[key] != nil {
		b.mu.Unlock()
		return b.reject(frame.ChannelID, failForwardInvalidRequest)
	}
	b.contexts[key] = context
	b.closeWg.Add(1)
	b.mu.Unlock()

	if err := context.connect(); err != nil {
		b.closeWg.Done()
		b.removeContext(context)
		context.close(false)
		return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardFreeContext, contextID, nil))
	}
	return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardActiveMaster, contextID, nil))
}

func (b *ForwardBridge) handleData(frame protocol.Frame) error {
	contextID, data, err := decodeForwardData(frame.Payload)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}
	key := forwardContextKey{channelID: frame.ChannelID, contextID: contextID}
	b.mu.Lock()
	context := b.contexts[key]
	reverse := b.reverseConns[key]
	b.mu.Unlock()
	if reverse != nil {
		if !reverse.write(data) {
			b.removeReverseConn(reverse)
			reverse.close(false)
			return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardFreeContext, contextID, nil))
		}
		return nil
	}
	if context == nil || !context.write(data) {
		if context != nil {
			b.removeContext(context)
			context.close(false)
		}
		return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardFreeContext, contextID, nil))
	}
	return nil
}

func (b *ForwardBridge) handleFreeContext(frame protocol.Frame) error {
	contextID, _, err := decodeForwardData(frame.Payload)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}
	key := forwardContextKey{channelID: frame.ChannelID, contextID: contextID}
	b.mu.Lock()
	context := b.contexts[key]
	reverse := b.reverseConns[key]
	binding := b.bindings[frame.ChannelID]
	reverseBind := b.reverseBindings[frame.ChannelID]
	isCheckContext := binding != nil && binding.checkContextID == contextID
	isReverseCheckContext := reverseBind != nil && reverseBind.checkContextID == contextID
	b.mu.Unlock()
	if context != nil {
		b.removeContext(context)
		context.close(false)
	}
	if reverse != nil {
		b.removeReverseConn(reverse)
		reverse.close(false)
	}
	if isCheckContext {
		b.removeBinding(binding)
		binding.close()
	}
	if isReverseCheckContext {
		b.removeReverseBinding(reverseBind)
		reverseBind.close()
	}
	return nil
}

func (b *ForwardBridge) runBinding(binding *forwardBinding) {
	b.runSetup(binding)
	<-binding.done
	binding.cleanupTargetForward()
}

func (b *ForwardBridge) runSetup(binding *forwardBinding) {
	if b.openTarget == nil {
		b.finishSetup(binding, fmt.Errorf("%s", failForwardSetup))
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, b.setupTimeout)
	defer cancel()
	target, err := b.openTarget(ctx, "fport tcp:"+strconv.Itoa(binding.localPort)+" "+binding.remoteEndpoint)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("%s", failForwardTimeout)
		} else {
			err = fmt.Errorf("%s", failForwardSetup)
		}
		b.finishSetup(binding, err)
		return
	}
	if !binding.attachTarget(target) {
		_ = target.Close()
		return
	}

	readDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = target.Close()
		case <-readDone:
		}
	}()

	var readErr error
	for {
		payload, currentErr := target.ReadPayload()
		if len(payload) > 0 {
			binding.recordOutput(payload)
		}
		if currentErr != nil {
			readErr = currentErr
			break
		}
	}
	close(readDone)
	_ = target.Close()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		readErr = fmt.Errorf("%s", failForwardTimeout)
	} else if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
		readErr = nil
	}
	b.finishSetup(binding, readErr)
}

func (b *ForwardBridge) finishSetup(binding *forwardBinding, setupErr error) {
	if setupErr == nil && binding.setupSuccessful() {
		if !binding.markReady() {
			return
		}
		_ = b.write(b.encodeForwardFrame(binding.channelID, protocol.CommandForwardCheckResult, binding.checkContextID, []byte{0}))
		return
	}

	message := failForwardNoResult
	if setupErr != nil {
		message = setupErr.Error()
	} else if binding.hasOutputError() {
		message = failForwardSetup
	}
	b.removeBinding(binding)
	binding.close()
	_ = b.write(b.codec.EncodeEchoAndClose(binding.channelID, message))
}

func (b *ForwardBridge) removeBinding(binding *forwardBinding) {
	if binding == nil {
		return
	}
	b.mu.Lock()
	if b.bindings[binding.channelID] == binding {
		delete(b.bindings, binding.channelID)
	}
	contexts := b.takeContextsLocked(binding.channelID)
	b.mu.Unlock()
	for _, context := range contexts {
		context.close(false)
	}
}

func (b *ForwardBridge) removeContext(context *forwardTCPContext) {
	if context == nil {
		return
	}
	b.mu.Lock()
	if b.contexts[context.key] == context {
		delete(b.contexts, context.key)
	}
	b.mu.Unlock()
}

func (b *ForwardBridge) takeContextsLocked(channelID uint32) []*forwardTCPContext {
	contexts := make([]*forwardTCPContext, 0)
	for key, context := range b.contexts {
		if key.channelID == channelID {
			contexts = append(contexts, context)
			delete(b.contexts, key)
		}
	}
	return contexts
}

func (b *ForwardBridge) reject(channelID uint32, message string) error {
	return b.write(b.codec.EncodeEchoAndClose(channelID, message))
}

func (b *ForwardBridge) encodeForwardFrame(channelID uint32, command protocol.Command, contextID uint32, data []byte) []byte {
	payload := make([]byte, forwardContextBytes+len(data))
	binary.BigEndian.PutUint32(payload[:forwardContextBytes], contextID)
	copy(payload[forwardContextBytes:], data)
	return b.codec.EncodeFrame(channelID, command, payload)
}

type forwardBinding struct {
	owner          *ForwardBridge
	channelID      uint32
	checkContextID uint32
	remoteEndpoint string
	localPort      int
	done           chan struct{}

	mu          sync.Mutex
	target      TargetChannel
	ready       bool
	outputSeen  bool
	outputError bool
	output      strings.Builder
	closed      bool
	closeOnce   sync.Once
}

func (b *forwardBinding) attachTarget(target TargetChannel) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.target = target
	return true
}

func (b *forwardBinding) recordOutput(payload []byte) {
	text := string(payload)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.outputSeen = true
	remaining := forwardOutputBytes - b.output.Len()
	if remaining > 0 {
		if len(text) > remaining {
			text = text[:remaining]
		}
		b.output.WriteString(text)
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "[fail]") || strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
		b.outputError = true
	}
}

func (b *forwardBinding) setupSuccessful() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.outputSeen && !b.outputError && strings.Contains(
		strings.ToLower(b.output.String()),
		"forwardport result:ok",
	)
}

func (b *forwardBinding) hasOutputError() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.outputError
}

func (b *forwardBinding) markReady() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.ready {
		return false
	}
	b.ready = true
	return true
}

func (b *forwardBinding) isReady() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ready && !b.closed
}

func (b *forwardBinding) close() {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		target := b.target
		b.target = nil
		b.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
		close(b.done)
	})
}

func (b *forwardBinding) cleanupTargetForward() {
	if b.owner.openTarget == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(b.owner.ctx), b.owner.setupTimeout)
	defer cancel()
	// 主 HDC 删除转发需完整 ruler（本地端点 + 设备端点），单端点删除会失败并泄漏转发规则。
	command := "fport rm tcp:" + strconv.Itoa(b.localPort) + " " + b.remoteEndpoint
	target, err := b.owner.openTarget(ctx, command)
	if err != nil {
		return
	}
	defer target.Close()
	for {
		if _, err := target.ReadPayload(); err != nil {
			return
		}
	}
}

type forwardContextKey struct {
	channelID uint32
	contextID uint32
}

type forwardTCPContext struct {
	owner   *ForwardBridge
	key     forwardContextKey
	binding *forwardBinding

	mu        sync.Mutex
	conn      net.Conn
	closed    bool
	closeOnce sync.Once
	writeMu   sync.Mutex
}

func (c *forwardTCPContext) connect() error {
	ctx, cancel := context.WithTimeout(c.owner.ctx, c.owner.setupTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.binding.localPort)))
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	c.conn = conn
	c.mu.Unlock()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	go func() {
		defer c.owner.closeWg.Done()
		c.readLoop()
	}()
	return nil
}

func (c *forwardTCPContext) write(data []byte) bool {
	c.mu.Lock()
	conn := c.conn
	closed := c.closed
	c.mu.Unlock()
	if closed || conn == nil {
		return false
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil || written <= 0 {
			return false
		}
		data = data[written:]
	}
	return true
}

func (c *forwardTCPContext) readLoop() {
	buffer := make([]byte, forwardBufferBytes)
	for {
		c.mu.Lock()
		conn := c.conn
		closed := c.closed
		c.mu.Unlock()
		if closed || conn == nil {
			return
		}
		count, err := conn.Read(buffer)
		if count > 0 {
			payload := c.owner.encodeForwardFrame(c.key.channelID, protocol.CommandForwardData, c.key.contextID, buffer[:count])
			if writeErr := c.owner.write(payload); writeErr != nil {
				c.owner.removeContext(c)
				c.close(false)
				return
			}
		}
		if err != nil {
			c.owner.removeContext(c)
			c.close(true)
			return
		}
	}
}

func (c *forwardTCPContext) close(notifyRemote bool) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		conn := c.conn
		c.conn = nil
		c.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		if notifyRemote {
			_ = c.owner.write(c.owner.encodeForwardFrame(c.key.channelID, protocol.CommandForwardFreeContext, c.key.contextID, nil))
		}
	})
}

func allocateForwardPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port <= 0 {
		return 0, fmt.Errorf("forward listener returned invalid port")
	}
	return address.Port, nil
}

func decodeForwardEndpoint(payload []byte) (uint32, string, error) {
	contextID, data, err := decodeForwardData(payload)
	if err != nil {
		return 0, "", err
	}
	if len(data) <= forwardPaddingBytes {
		return 0, "", fmt.Errorf("%s", failForwardInvalidRequest)
	}
	for _, value := range data[:forwardPaddingBytes] {
		if value != 0 {
			return 0, "", fmt.Errorf("%s", failForwardInvalidRequest)
		}
	}
	endpointBytes := data[forwardPaddingBytes:]
	if zero := bytesIndex(endpointBytes, 0); zero >= 0 {
		for _, value := range endpointBytes[zero+1:] {
			if value != 0 {
				return 0, "", fmt.Errorf("%s", failForwardInvalidRequest)
			}
		}
		endpointBytes = endpointBytes[:zero]
	}
	endpoint := string(endpointBytes)
	if err := validateForwardEndpoint(endpoint); err != nil {
		return 0, "", err
	}
	return contextID, endpoint, nil
}

// allowedSocketSchemas 是除 tcp 外放行的 forward 端点 schema（Unix 域套接字族）。
// 本地桥接侧恒为 TCP，设备侧 schema 由主 HDC 透传处理。
var allowedSocketSchemas = []string{"localabstract:", "localreserved:", "localfilesystem:"}

// forwardEndpointMaxBytes 限制端点串长度，防止超长串被拼进主 HDC 命令行。
const forwardEndpointMaxBytes = 512

// validateForwardEndpoint 校验 forward 端点：tcp: 限数字端口；localabstract/localreserved/localfilesystem
// 的 content 走严格字符集校验。端点串会被拼进主 HDC 命令行（按空白分词，非 shell），
// 故用可穷尽白名单挡住注入面；其余 schema（jdwp/ark/dev 等）一律 fail-closed。
func validateForwardEndpoint(endpoint string) error {
	if endpoint == "" || len(endpoint) > forwardEndpointMaxBytes {
		return fmt.Errorf("%s", failForwardUnsupported)
	}
	if content, ok := strings.CutPrefix(endpoint, "tcp:"); ok {
		port, err := strconv.Atoi(content)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("%s", failForwardInvalidRequest)
		}
		return nil
	}
	for _, schema := range allowedSocketSchemas {
		if content, ok := strings.CutPrefix(endpoint, schema); ok {
			return validateSocketEndpointContent(content)
		}
	}
	return fmt.Errorf("%s", failForwardUnsupported)
}

// validateSocketEndpointContent 校验域套接字端点的名称/路径部分：非空、无前导 '-'（防被主 HDC 当作选项），
// 且仅允许 [A-Za-z0-9_.-/]（排除空白、控制字符与 shell 元字符）。
func validateSocketEndpointContent(content string) error {
	if content == "" || strings.HasPrefix(content, "-") {
		return fmt.Errorf("%s", failForwardInvalidRequest)
	}
	for _, value := range content {
		if !isSocketEndpointRune(value) {
			return fmt.Errorf("%s", failForwardInvalidRequest)
		}
	}
	return nil
}

func isSocketEndpointRune(value rune) bool {
	switch {
	case value >= 'a' && value <= 'z':
		return true
	case value >= 'A' && value <= 'Z':
		return true
	case value >= '0' && value <= '9':
		return true
	default:
		return strings.ContainsRune("_.-/", value)
	}
}

func decodeForwardData(payload []byte) (uint32, []byte, error) {
	if len(payload) < forwardContextBytes {
		return 0, nil, fmt.Errorf("%s", failForwardInvalidRequest)
	}
	contextID := binary.BigEndian.Uint32(payload[:forwardContextBytes])
	return contextID, append([]byte(nil), payload[forwardContextBytes:]...), nil
}

func bytesIndex(data []byte, value byte) int {
	for index, candidate := range data {
		if candidate == value {
			return index
		}
	}
	return -1
}
