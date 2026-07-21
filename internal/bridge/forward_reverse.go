package bridge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

// rport（反向端口转发）：本服务作为 forward master/listener。
// 与 fport（本服务为 slave）方向相反：设备监听 deviceEndpoint，反向转发到主机 hostEndpoint。
//
// 落地方式（主 HDC 与本服务同机）：
//  1. 本服务在本地开监听端口 gatewayPort。
//  2. 经主 HDC 执行 `rport <deviceEndpoint> tcp:<gatewayPort>`：设备监听 deviceEndpoint，
//     每条设备侧连接由主 HDC 作为 TCP client 连回本服务 gatewayPort。
//  3. 本服务 accept 到反向连接后，作为 forward master 向用户 server 发起 ACTIVE_SLAVE，
//     用户 server 连接 hostEndpoint 后回 ACTIVE_MASTER，随后双向 CMD_FORWARD_DATA 桥接。
//
// 真机校准点：主 HDC `rport` 的结果文本/时序、反向连接建立方式、CHECK_RESULT flag 语义、
// `fport rm` 对 reverse 任务的清理串，均需真机验收。

// handleReverseInit 处理 rport 发起帧（CMD_FORWARD_INIT，payload="deviceEndpoint hostEndpoint"）。
func (b *ForwardBridge) handleReverseInit(frame protocol.Frame) error {
	deviceEndpoint, hostEndpoint, message := parseReverseCommand(frame.Payload)
	if message != "" {
		return b.reject(frame.ChannelID, message)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return b.reject(frame.ChannelID, failForwardSetup)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port <= 0 {
		_ = listener.Close()
		return b.reject(frame.ChannelID, failForwardSetup)
	}
	binding := &reverseBinding{
		owner:          b,
		channelID:      frame.ChannelID,
		checkContextID: randomContextID(),
		deviceEndpoint: deviceEndpoint,
		hostEndpoint:   hostEndpoint,
		listener:       listener,
		gatewayPort:    address.Port,
		done:           make(chan struct{}),
	}

	b.mu.Lock()
	if b.closed || b.reverseBindings[frame.ChannelID] != nil || b.bindings[frame.ChannelID] != nil {
		b.mu.Unlock()
		_ = listener.Close()
		return b.reject(frame.ChannelID, failForwardInvalidRequest)
	}
	b.reverseBindings[frame.ChannelID] = binding
	b.closeWg.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.closeWg.Done()
		b.runReverse(binding)
	}()
	return nil
}

func (b *ForwardBridge) runReverse(binding *reverseBinding) {
	b.runReverseSetup(binding)
	<-binding.done
	binding.stopListener()
	binding.cleanupTargetForward()
}

// runReverseSetup 经主 HDC 建立设备侧 rport，成功后启动 accept 循环并向用户发送 CMD_FORWARD_CHECK。
func (b *ForwardBridge) runReverseSetup(binding *reverseBinding) {
	if b.openTarget == nil {
		b.failReverseSetup(binding, fmt.Errorf("%s", failForwardSetup))
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, b.setupTimeout)
	defer cancel()
	command := "rport " + binding.deviceEndpoint + " tcp:" + strconv.Itoa(binding.gatewayPort)
	target, err := b.openTarget(ctx, command)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			b.failReverseSetup(binding, fmt.Errorf("%s", failForwardTimeout))
		} else {
			b.failReverseSetup(binding, fmt.Errorf("%s", failForwardSetup))
		}
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
		b.failReverseSetup(binding, fmt.Errorf("%s", failForwardTimeout))
		return
	}
	// 读循环仅在出错时退出（含正常的 EOF/ErrClosed 表示 rport 一次性命令通道关闭）。
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
		b.failReverseSetup(binding, fmt.Errorf("%s", failForwardSetup))
		return
	}
	if !binding.setupSuccessful() {
		b.failReverseSetup(binding, fmt.Errorf("%s", failForwardNoResult))
		return
	}
	if !binding.markReady() {
		return
	}
	b.closeWg.Add(1)
	go func() {
		defer b.closeWg.Done()
		b.reverseAcceptLoop(binding)
	}()
	// master 侧发起可达性校验：请用户 server 验证 hostEndpoint 可连接。
	// 关键：master 任务必须先发 CMD_KERNEL_WAKEUP_SLAVETASK 唤醒对端，
	// 让用户 server 创建 host 侧 forward slave 任务，否则后续 CHECK 会因对端无任务而被丢弃。
	b.debug("rport setup ok, sending WAKEUP + CHECK", "channel", binding.channelID, "ctx", binding.checkContextID, "host", binding.hostEndpoint, "gatewayPort", binding.gatewayPort)
	_ = b.write(b.codec.EncodeFrame(binding.channelID, protocol.CommandKernelWakeupSlaveTask, nil))
	_ = b.write(b.encodeForwardEndpointFrame(binding.channelID, protocol.CommandForwardCheck, binding.checkContextID, binding.hostEndpoint))

	// 若用户 server 在超时内未回 CHECK_RESULT，则失败收尾，避免客户端无限挂起。
	b.closeWg.Add(1)
	go func() {
		defer b.closeWg.Done()
		timer := time.NewTimer(b.setupTimeout)
		defer timer.Stop()
		select {
		case <-binding.done:
		case <-timer.C:
			if !binding.isResolved() {
				b.debug("rport CHECK timed out, no CHECK_RESULT", "channel", binding.channelID)
				b.failReverseSetup(binding, fmt.Errorf("%s", failForwardTimeout))
			}
		}
	}()
}

func (b *ForwardBridge) failReverseSetup(binding *reverseBinding, setupErr error) {
	message := failForwardNoResult
	if setupErr != nil {
		message = setupErr.Error()
	} else if binding.hasOutputError() {
		message = failForwardSetup
	}
	b.removeReverseBinding(binding)
	binding.close()
	_ = b.write(b.codec.EncodeEchoAndClose(binding.channelID, message))
}

// reverseAcceptLoop 接收主 HDC 反向连回的连接，每条连接向用户 server 发起 ACTIVE_SLAVE。
func (b *ForwardBridge) reverseAcceptLoop(binding *reverseBinding) {
	for {
		conn, err := binding.listener.Accept()
		if err != nil {
			return
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
		key := forwardContextKey{channelID: binding.channelID, contextID: randomContextID()}
		reverse := &reverseConn{owner: b, key: key, conn: conn}
		b.mu.Lock()
		if b.closed || b.reverseBindings[binding.channelID] != binding {
			b.mu.Unlock()
			_ = conn.Close()
			return
		}
		b.reverseConns[key] = reverse
		b.mu.Unlock()
		if err := b.write(b.encodeForwardEndpointFrame(binding.channelID, protocol.CommandForwardActiveSlave, key.contextID, binding.hostEndpoint)); err != nil {
			b.removeReverseConn(reverse)
			reverse.close(false)
			return
		}
	}
}

// handleReverseCheckResult 处理用户 server 对 CMD_FORWARD_CHECK 的应答；flag 字节 0 表示 hostEndpoint 可达。
func (b *ForwardBridge) handleReverseCheckResult(frame protocol.Frame) error {
	contextID, data, err := decodeForwardData(frame.Payload)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}
	b.mu.Lock()
	binding := b.reverseBindings[frame.ChannelID]
	b.mu.Unlock()
	b.debug("rport CHECK_RESULT received", "channel", frame.ChannelID, "ctx", contextID, "data", data, "hasBinding", binding != nil)
	if binding == nil || binding.checkContextID != contextID {
		return nil
	}
	binding.markResolved()
	ok := len(data) >= 1 && data[0] == 0
	if !ok {
		b.removeReverseBinding(binding)
		binding.close()
		return b.write(b.codec.EncodeEchoAndClose(frame.ChannelID, failForwardSetup))
	}
	return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardSuccess, binding.checkContextID, nil))
}

// handleReverseActiveMaster 处理用户 server 连接 hostEndpoint 成功后的 ACTIVE_MASTER，启动数据泵。
func (b *ForwardBridge) handleReverseActiveMaster(frame protocol.Frame) error {
	contextID, _, err := decodeForwardData(frame.Payload)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}
	key := forwardContextKey{channelID: frame.ChannelID, contextID: contextID}
	b.mu.Lock()
	reverse := b.reverseConns[key]
	b.mu.Unlock()
	if reverse == nil {
		return b.write(b.encodeForwardFrame(frame.ChannelID, protocol.CommandForwardFreeContext, contextID, nil))
	}
	if !reverse.start() {
		return nil
	}
	b.closeWg.Add(1)
	go func() {
		defer b.closeWg.Done()
		reverse.readLoop()
	}()
	return nil
}

func (b *ForwardBridge) removeReverseBinding(binding *reverseBinding) {
	if binding == nil {
		return
	}
	b.mu.Lock()
	if b.reverseBindings[binding.channelID] == binding {
		delete(b.reverseBindings, binding.channelID)
	}
	reverses := b.takeReverseConnsLocked(binding.channelID)
	b.mu.Unlock()
	for _, reverse := range reverses {
		reverse.close(false)
	}
}

func (b *ForwardBridge) removeReverseConn(reverse *reverseConn) {
	if reverse == nil {
		return
	}
	b.mu.Lock()
	if b.reverseConns[reverse.key] == reverse {
		delete(b.reverseConns, reverse.key)
	}
	b.mu.Unlock()
}

func (b *ForwardBridge) takeReverseConnsLocked(channelID uint32) []*reverseConn {
	reverses := make([]*reverseConn, 0)
	for key, reverse := range b.reverseConns {
		if key.channelID == channelID {
			reverses = append(reverses, reverse)
			delete(b.reverseConns, key)
		}
	}
	return reverses
}

// encodeForwardEndpointFrame 构造带端点参数的 forward 帧：[4 字节 ctxid][8 字节保留位][端点串][0]。
func (b *ForwardBridge) encodeForwardEndpointFrame(channelID uint32, command protocol.Command, contextID uint32, endpoint string) []byte {
	data := make([]byte, forwardPaddingBytes+len(endpoint)+1)
	copy(data[forwardPaddingBytes:], endpoint)
	return b.encodeForwardFrame(channelID, command, contextID, data)
}

type reverseBinding struct {
	owner          *ForwardBridge
	channelID      uint32
	checkContextID uint32
	deviceEndpoint string
	hostEndpoint   string
	listener       net.Listener
	gatewayPort    int
	done           chan struct{}

	mu          sync.Mutex
	target      TargetChannel
	ready       bool
	resolved    bool
	outputSeen  bool
	outputError bool
	output      strings.Builder
	closed      bool
	closeOnce   sync.Once
}

func (r *reverseBinding) markResolved() {
	r.mu.Lock()
	r.resolved = true
	r.mu.Unlock()
}

func (r *reverseBinding) isResolved() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolved
}

func (r *reverseBinding) attachTarget(target TargetChannel) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.target = target
	return true
}

func (r *reverseBinding) recordOutput(payload []byte) {
	text := string(payload)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.outputSeen = true
	remaining := forwardOutputBytes - r.output.Len()
	if remaining > 0 {
		if len(text) > remaining {
			text = text[:remaining]
		}
		r.output.WriteString(text)
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "[fail]") || strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
		r.outputError = true
	}
}

func (r *reverseBinding) setupSuccessful() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.outputSeen && !r.outputError && strings.Contains(strings.ToLower(r.output.String()), "forwardport result:ok")
}

func (r *reverseBinding) hasOutputError() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.outputError
}

func (r *reverseBinding) markReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ready {
		return false
	}
	r.ready = true
	return true
}

func (r *reverseBinding) stopListener() {
	r.mu.Lock()
	listener := r.listener
	r.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
}

func (r *reverseBinding) close() {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		target := r.target
		r.target = nil
		listener := r.listener
		r.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		close(r.done)
	})
}

// cleanupTargetForward 尽力删除设备侧 rport 任务。主 HDC 删除转发需完整 ruler（创建时的
// "<deviceEndpoint> tcp:<gatewayPort>"），且不带 rport 关键字，否则删除失败并泄漏反向转发规则。
func (r *reverseBinding) cleanupTargetForward() {
	if r.owner.openTarget == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.owner.ctx), r.owner.setupTimeout)
	defer cancel()
	command := "fport rm " + r.deviceEndpoint + " tcp:" + strconv.Itoa(r.gatewayPort)
	target, err := r.owner.openTarget(ctx, command)
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

type reverseConn struct {
	owner *ForwardBridge
	key   forwardContextKey
	conn  net.Conn

	mu        sync.Mutex
	started   bool
	closed    bool
	closeOnce sync.Once
	writeMu   sync.Mutex
}

func (c *reverseConn) start() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.started {
		return false
	}
	c.started = true
	return true
}

func (c *reverseConn) write(data []byte) bool {
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

func (c *reverseConn) readLoop() {
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
				c.owner.removeReverseConn(c)
				c.close(false)
				return
			}
		}
		if err != nil {
			c.owner.removeReverseConn(c)
			c.close(true)
			return
		}
	}
}

func (c *reverseConn) close(notifyRemote bool) {
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

// parseReverseCommand 解析 rport 发起负载 "deviceEndpoint hostEndpoint"（server 已剥离 rport 关键字）。
// 端点支持 tcp 与 localabstract/localreserved/localfilesystem。
func parseReverseCommand(payload []byte) (deviceEndpoint, hostEndpoint, message string) {
	text := string(payload)
	if strings.ContainsAny(text, "\x00\r\n") {
		return "", "", failForwardInvalidRequest
	}
	fields := strings.Fields(text)
	if len(fields) != 2 {
		return "", "", failForwardInvalidRequest
	}
	if !validReverseEndpoint(fields[0]) || !validReverseEndpoint(fields[1]) {
		return "", "", failForwardUnsupported
	}
	return fields[0], fields[1], ""
}

func validReverseEndpoint(endpoint string) bool {
	return validateForwardEndpoint(endpoint) == nil
}

func randomContextID() uint32 {
	var buffer [4]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return 1
	}
	value := binary.BigEndian.Uint32(buffer[:])
	if value == 0 {
		value = 1
	}
	return value
}
