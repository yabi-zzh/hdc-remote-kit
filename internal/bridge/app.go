package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

const (
	appFinishModeInstall   = byte(1)
	appFinishModeUninstall = byte(2)
	appStatusFail          = byte(0)
	appStatusSuccess       = byte(1)
	appResultLimit         = 64 * 1024
)

const (
	failAppInvalidRequest  = "[Fail] App request is invalid."
	failAppUnsupported     = "[Fail] App command is not supported."
	failAppUnsupportedPkg  = "[Fail] App package is not supported."
	failAppUnsupportedOpt  = "[Fail] App option is not supported."
	failAppUnsupportedComp = "[Fail] Compressed app transfer is not supported."
	failAppTransfer        = "[Fail] App transfer failed."
	failAppCommand         = "[Fail] App command failed."
	failAppNoResult        = "[Fail] App command did not return a result."
	failAppTimeout         = "[Fail] App command timed out."
)

var (
	installOptions   = map[string]struct{}{"-r": {}, "-s": {}}
	uninstallOptions = map[string]struct{}{"-k": {}, "-s": {}}
)

// AppBridge 处理 app 族：install（收临时包→按原名重命名→经主 HDC install）与 uninstall（直达主 HDC uninstall）。
// 仅支持 .hap/.hsp/.app 单包与受限选项，压缩/目录 tar/未知帧 fail-closed。
type AppBridge struct {
	ctx         context.Context
	codec       *protocol.Codec
	tempStore   *TempStore
	maxAppBytes int64
	timeout     time.Duration
	openTarget  OpenTargetFunc
	write       FrameWriter

	mu       sync.Mutex
	sessions map[uint32]*appSession
	closed   bool
	closeWg  sync.WaitGroup
}

// NewAppBridge 构造 app 族桥接（install/uninstall）；openTarget 打开主 HDC target channel，write 回写用户连接。
func NewAppBridge(
	ctx context.Context,
	codec *protocol.Codec,
	tempStore *TempStore,
	maxAppBytes int64,
	timeout time.Duration,
	openTarget OpenTargetFunc,
	write FrameWriter,
) *AppBridge {
	return &AppBridge{
		ctx: ctx, codec: codec, tempStore: tempStore, maxAppBytes: maxAppBytes,
		timeout: timeout, openTarget: openTarget, write: write,
		sessions: make(map[uint32]*appSession),
	}
}

// Handle 分派 app 族帧：install 的 INIT/CHECK/DATA 与 uninstall，其余 fail-closed。
func (b *AppBridge) Handle(frame protocol.Frame) error {
	switch frame.CommandFlag {
	case protocol.CommandAppInit:
		return b.handleInstallInit(frame)
	case protocol.CommandAppCheck:
		return b.handleInstallCheck(frame)
	case protocol.CommandAppData:
		return b.handleInstallData(frame)
	case protocol.CommandAppUninstall:
		return b.handleUninstall(frame)
	case protocol.CommandAppBegin, protocol.CommandAppFinish:
		return b.reject(frame.ChannelID, failAppUnsupported)
	default:
		return b.reject(frame.ChannelID, failAppUnsupported)
	}
}

// CloseChannel 关闭指定 channel 上的安装/卸载会话（收到 ChannelClose 时调用）。
func (b *AppBridge) CloseChannel(channelID uint32) {
	b.mu.Lock()
	session := b.sessions[channelID]
	delete(b.sessions, channelID)
	b.mu.Unlock()
	if session != nil {
		session.close()
	}
}

// Close 关闭 app 桥：终止所有进行中的安装/卸载会话，释放临时包并等待其 goroutine 退出。
func (b *AppBridge) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	sessions := make([]*appSession, 0, len(b.sessions))
	for channelID, session := range b.sessions {
		sessions = append(sessions, session)
		delete(b.sessions, channelID)
	}
	b.mu.Unlock()

	for _, session := range sessions {
		session.close()
	}
	b.closeWg.Wait()
}

func (b *AppBridge) handleInstallInit(frame protocol.Frame) error {
	session := b.getOrCreate(frame.ChannelID)
	if session == nil {
		return b.reject(frame.ChannelID, failAppInvalidRequest)
	}
	if err := session.startInstallInit(frame.Payload); err != nil {
		return b.write(session.protocolFailure(appFinishModeInstall, err.Error()))
	}
	return nil
}

func (b *AppBridge) handleInstallCheck(frame protocol.Frame) error {
	session := b.getOrCreate(frame.ChannelID)
	if session == nil {
		return b.reject(frame.ChannelID, failAppInvalidRequest)
	}
	begin, err := session.prepareInstall(frame.Payload)
	if err != nil {
		return b.write(session.protocolFailure(appFinishModeInstall, err.Error()))
	}
	return b.write(begin)
}

func (b *AppBridge) handleInstallData(frame protocol.Frame) error {
	session := b.get(frame.ChannelID)
	if session == nil {
		return b.reject(frame.ChannelID, failAppInvalidRequest)
	}
	if err := session.writeInstallData(frame.Payload); err != nil {
		return b.write(session.protocolFailure(appFinishModeInstall, err.Error()))
	}
	return nil
}

func (b *AppBridge) handleUninstall(frame protocol.Frame) error {
	session := b.getOrCreate(frame.ChannelID)
	if session == nil {
		return b.reject(frame.ChannelID, failAppInvalidRequest)
	}
	if err := session.startUninstall(frame.Payload); err != nil {
		return b.write(session.protocolFailure(appFinishModeUninstall, err.Error()))
	}
	return nil
}

func (b *AppBridge) get(channelID uint32) *appSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessions[channelID]
}

func (b *AppBridge) getOrCreate(channelID uint32) *appSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if session := b.sessions[channelID]; session != nil {
		return session
	}
	session := &appSession{owner: b, channelID: channelID}
	b.sessions[channelID] = session
	return session
}

func (b *AppBridge) launch(session *appSession, mode byte, command string, cleanup *tempAllocation) bool {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return false
	}
	b.closeWg.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.closeWg.Done()
		session.runTargetCommand(mode, command, cleanup)
	}()
	return true
}

func (b *AppBridge) reject(channelID uint32, message string) error {
	return b.write(b.codec.EncodeEchoAndClose(channelID, message))
}

type appSession struct {
	owner     *AppBridge
	channelID uint32

	mu             sync.Mutex
	closed         bool
	commandRunning bool
	target         TargetChannel
	transfer       *appTransfer
	output         strings.Builder
	outputSeen     bool
	failureSeen    bool
	closeOnce      sync.Once
}

type appTransfer struct {
	allocation   *tempAllocation
	expectedSize int64
	optionalName string
	options      string
	receivedSize int64
}

func (s *appSession) startInstallInit(payload []byte) error {
	command, err := decodeAppCommand(payload)
	if err != nil {
		return err
	}
	arguments, err := splitAppArguments(command)
	if err != nil {
		return err
	}
	if err := validateInstallCommand(arguments); err != nil {
		return err
	}

	s.mu.Lock()
	if err := s.ensureAvailableLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.commandRunning = true
	s.resetOutputLocked()
	s.mu.Unlock()

	if !s.owner.launch(s, appFinishModeInstall, strings.TrimSpace(command), nil) {
		return fmt.Errorf("%s", failAppCommand)
	}
	return nil
}

func (s *appSession) prepareInstall(payload []byte) ([]byte, error) {
	config, err := protocol.DecodeTransferConfig(payload)
	if err != nil {
		return nil, fmt.Errorf("%s", failAppInvalidRequest)
	}
	if err := s.validateInstallConfig(config); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureAvailableLocked(); err != nil {
		return nil, err
	}
	if s.owner.tempStore == nil {
		return nil, fmt.Errorf("%s", failAppTransfer)
	}
	allocation, err := s.owner.tempStore.allocate(int64(config.FileSize))
	if err != nil {
		return nil, fmt.Errorf("%s", failAppTransfer)
	}
	s.transfer = &appTransfer{
		allocation: allocation, expectedSize: int64(config.FileSize),
		optionalName: config.OptionalName, options: normalizeAppOptionText(config.Options),
	}
	return s.owner.codec.EncodeFrame(s.channelID, protocol.CommandAppBegin, nil), nil
}

func (s *appSession) writeInstallData(payload []byte) error {
	maxBytes := uint32(^uint32(0))
	if s.owner.maxAppBytes < int64(maxBytes) {
		maxBytes = uint32(s.owner.maxAppBytes)
	}
	header, data, err := protocol.DecodeTransferData(payload, maxBytes)
	if err != nil {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	if len(payload) != protocol.TransferPayloadPrefixBytes+int(header.CompressedSize) {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	if header.Compression != protocol.CompressionNone {
		return fmt.Errorf("%s", failAppUnsupportedComp)
	}
	if header.CompressedSize != header.UncompressedSize {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}

	var completed *appTransfer
	s.mu.Lock()
	if s.closed || s.commandRunning {
		s.mu.Unlock()
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	transfer := s.transfer
	if transfer == nil || s.commandRunning || header.Index != uint64(transfer.receivedSize) {
		s.mu.Unlock()
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	chunkSize := int64(len(data))
	if chunkSize > transfer.expectedSize-transfer.receivedSize {
		s.mu.Unlock()
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	chunkEnd := transfer.receivedSize + chunkSize
	if chunkEnd < transfer.receivedSize || chunkEnd > transfer.expectedSize {
		s.mu.Unlock()
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	written, writeErr := transfer.allocation.file.WriteAt(data, transfer.receivedSize)
	if writeErr != nil || written != len(data) {
		s.mu.Unlock()
		return fmt.Errorf("%s", failAppTransfer)
	}
	transfer.receivedSize = chunkEnd
	if transfer.receivedSize == transfer.expectedSize {
		if err := transfer.allocation.seal(); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("%s", failAppTransfer)
		}
		// 设备侧 bm install 依赖文件扩展名识别包类型，需把临时文件恢复为带原始扩展名的包名。
		if err := transfer.allocation.renameToName(transfer.optionalName); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("%s", failAppTransfer)
		}
		completed = transfer
		s.transfer = nil
		s.commandRunning = true
		s.resetOutputLocked()
	}
	s.mu.Unlock()

	if completed != nil {
		command := buildAppInstallCommand(completed.options, completed.allocation.path)
		if !s.owner.launch(s, appFinishModeInstall, command, completed.allocation) {
			completed.allocation.close()
			return fmt.Errorf("%s", failAppCommand)
		}
	}
	return nil
}

func (s *appSession) startUninstall(payload []byte) error {
	commandPayload, err := decodeAppCommand(payload)
	if err != nil {
		return err
	}
	arguments, err := splitAppArguments(commandPayload)
	if err != nil {
		return err
	}
	// hdc 客户端把整条输入作为 payload 下发，daemon 收到的 CMD_APP_UNINSTALL 负载以 "uninstall " 开头；
	// 剥离该关键字，仅保留选项与 bundle name（兼容不带前缀的直接调用）。
	if len(arguments) > 0 && arguments[0] == "uninstall" {
		arguments = arguments[1:]
	}
	if err := validateUninstallCommand(arguments); err != nil {
		return err
	}

	s.mu.Lock()
	if err := s.ensureAvailableLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.commandRunning = true
	s.resetOutputLocked()
	s.mu.Unlock()

	command := "uninstall " + strings.Join(arguments, " ")
	if !s.owner.launch(s, appFinishModeUninstall, command, nil) {
		return fmt.Errorf("%s", failAppCommand)
	}
	return nil
}

func (s *appSession) runTargetCommand(mode byte, command string, cleanup *tempAllocation) {
	if s.owner.openTarget == nil {
		s.finishTarget(mode, nil, cleanup, fmt.Errorf("%s", failAppCommand))
		return
	}
	ctx, cancel := context.WithTimeout(s.owner.ctx, s.owner.timeout)
	defer cancel()
	target, err := s.owner.openTarget(ctx, command)
	if err != nil {
		s.finishTarget(mode, nil, cleanup, err)
		return
	}
	if !s.attachTarget(target) {
		_ = target.Close()
		if cleanup != nil {
			cleanup.close()
		}
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
		var payload []byte
		payload, readErr = target.ReadPayload()
		if len(payload) > 0 {
			s.recordOutput(payload)
		}
		if readErr != nil {
			break
		}
	}
	close(readDone)

	resultErr := readErr
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		resultErr = fmt.Errorf("%s", failAppTimeout)
	} else if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
		resultErr = nil
	}
	s.finishTarget(mode, target, cleanup, resultErr)
}

func (s *appSession) attachTarget(target TargetChannel) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.commandRunning {
		return false
	}
	s.target = target
	return true
}

func (s *appSession) recordOutput(payload []byte) {
	if len(payload) == 0 {
		return
	}
	text := string(payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.outputSeen = true
	s.output.WriteString(text)
	if s.output.Len() > appResultLimit {
		value := s.output.String()
		s.output.Reset()
		s.output.WriteString(value[len(value)-appResultLimit:])
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "[fail]") || strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
		s.failureSeen = true
	}
}

func (s *appSession) finishTarget(mode byte, target TargetChannel, cleanup *tempAllocation, resultErr error) {
	s.mu.Lock()
	if s.closed || (target != nil && s.target != target) {
		s.mu.Unlock()
		if cleanup != nil {
			cleanup.close()
		}
		return
	}
	output := s.output.String()
	outputSeen := s.outputSeen
	failureSeen := s.failureSeen
	s.target = nil
	s.commandRunning = false
	s.resetOutputLocked()
	s.mu.Unlock()

	if target != nil {
		_ = target.Close()
	}
	if cleanup != nil {
		cleanup.close()
	}

	status := appStatusSuccess
	message := normalizeAppResult(output)
	if resultErr != nil || failureSeen || !outputSeen || message == "" {
		status = appStatusFail
		if resultErr != nil && strings.HasPrefix(resultErr.Error(), "[Fail]") {
			message = resultErr.Error()
		} else if message == "" {
			message = failAppNoResult
		}
	}
	if status == appStatusSuccess && message == "" {
		message = "Success"
	}
	_ = s.owner.write(s.encodeFinish(mode, status, message))
}

func (s *appSession) protocolFailure(mode byte, message string) []byte {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.encodeFinish(mode, appStatusFail, failAppInvalidRequest)
	}
	target := s.target
	allocation := (*tempAllocation)(nil)
	if s.transfer != nil {
		allocation = s.transfer.allocation
	}
	s.target = nil
	s.transfer = nil
	s.commandRunning = false
	s.resetOutputLocked()
	s.mu.Unlock()
	if target != nil {
		_ = target.Close()
	}
	if allocation != nil {
		allocation.close()
	}
	return s.encodeFinish(mode, appStatusFail, message)
}

func (s *appSession) encodeFinish(mode, status byte, message string) []byte {
	message = normalizeAppResult(message)
	if message == "" {
		message = failAppCommand
	}
	payload := make([]byte, 2+len(message))
	payload[0] = mode
	payload[1] = status
	copy(payload[2:], message)
	return s.owner.codec.EncodeFrame(s.channelID, protocol.CommandAppFinish, payload)
}

func (s *appSession) ensureAvailableLocked() error {
	if s.closed || s.commandRunning || s.transfer != nil {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	return nil
}

func (s *appSession) resetOutputLocked() {
	s.output.Reset()
	s.outputSeen = false
	s.failureSeen = false
}

func (s *appSession) close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		target := s.target
		allocation := (*tempAllocation)(nil)
		if s.transfer != nil {
			allocation = s.transfer.allocation
		}
		s.target = nil
		s.transfer = nil
		s.commandRunning = false
		s.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
		if allocation != nil {
			allocation.close()
		}
	})
}

func (s *appSession) validateInstallConfig(config protocol.TransferConfig) error {
	if config.FileSize > uint64(^uint64(0)>>1) || int64(config.FileSize) > s.owner.maxAppBytes {
		return fmt.Errorf("%s", failAppTransfer)
	}
	if config.FunctionName != "install" || config.Compression != protocol.CompressionNone {
		if config.FunctionName != "install" {
			return fmt.Errorf("%s", failAppUnsupported)
		}
		return fmt.Errorf("%s", failAppUnsupportedComp)
	}
	if config.UpdateIfNew || config.HoldTimestamp {
		return fmt.Errorf("%s", failAppUnsupportedOpt)
	}
	if _, err := normalizeAppOptions(config.Options, installOptions); err != nil {
		return err
	}
	if hasUnsafeText(config.Path) || hasUnsafeText(config.OptionalName) ||
		strings.ContainsAny(config.OptionalName, `/\\`) || !isSupportedAppPackage(config.OptionalName) {
		return fmt.Errorf("%s", failAppUnsupportedPkg)
	}
	return nil
}

func decodeAppCommand(payload []byte) (string, error) {
	if !utf8.Valid(payload) {
		return "", fmt.Errorf("%s", failAppInvalidRequest)
	}
	// hdc 客户端以 NUL 结尾传递命令串，先剥离首尾 NUL 与空白再校验。
	command := strings.TrimSpace(strings.Trim(string(payload), "\x00"))
	if command == "" || hasUnsafeText(command) || strings.ContainsAny(command, "|;&$<>`\\!") {
		return "", fmt.Errorf("%s", failAppInvalidRequest)
	}
	return command, nil
}

func splitAppArguments(command string) ([]string, error) {
	var arguments []string
	var current strings.Builder
	var quote rune
	escaped := false
	for _, value := range command {
		if escaped {
			current.WriteRune(value)
			escaped = false
			continue
		}
		if value == '\\' && quote == '"' {
			escaped = true
			continue
		}
		if (value == '\'' || value == '"') && (quote == 0 || quote == value) {
			if quote == 0 {
				quote = value
			} else {
				quote = 0
			}
			continue
		}
		if (value == ' ' || value == '\t') && quote == 0 {
			if current.Len() > 0 {
				arguments = append(arguments, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(value)
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("%s", failAppInvalidRequest)
	}
	if current.Len() > 0 {
		arguments = append(arguments, current.String())
	}
	return arguments, nil
}

func validateInstallCommand(arguments []string) error {
	if len(arguments) < 2 || arguments[0] != "install" {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	packageCount := 0
	for _, argument := range arguments[1:] {
		if strings.HasPrefix(argument, "-") {
			if _, ok := installOptions[argument]; !ok {
				return fmt.Errorf("%s", failAppUnsupportedOpt)
			}
			continue
		}
		packageCount++
		if hasUnsafeText(argument) || !isSupportedAppPackage(argument) {
			return fmt.Errorf("%s", failAppUnsupportedPkg)
		}
	}
	if packageCount != 1 {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	return nil
}

func validateUninstallCommand(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	packageSeen := false
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") {
			if _, ok := uninstallOptions[argument]; !ok {
				return fmt.Errorf("%s", failAppUnsupportedOpt)
			}
			continue
		}
		if packageSeen || hasUnsafeText(argument) || strings.ContainsAny(argument, `/\\`) {
			return fmt.Errorf("%s", failAppInvalidRequest)
		}
		packageSeen = true
	}
	if !packageSeen {
		return fmt.Errorf("%s", failAppInvalidRequest)
	}
	return nil
}

func normalizeAppOptions(value string, supported map[string]struct{}) (string, error) {
	if hasUnsafeText(value) {
		return "", fmt.Errorf("%s", failAppInvalidRequest)
	}
	arguments, err := splitAppArguments(value)
	if err != nil {
		return "", err
	}
	for _, argument := range arguments {
		if _, ok := supported[argument]; !ok {
			return "", fmt.Errorf("%s", failAppUnsupportedOpt)
		}
	}
	return strings.Join(arguments, " "), nil
}

func normalizeAppOptionText(value string) string {
	arguments, _ := splitAppArguments(value)
	return strings.Join(arguments, " ")
}

func buildAppInstallCommand(options, localPath string) string {
	command := "install"
	if options != "" {
		command += " " + options
	}
	return command + " " + quoteCommandArg(localPath)
}

func isSupportedAppPackage(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasSuffix(lower, ".hap") || strings.HasSuffix(lower, ".hsp") || strings.HasSuffix(lower, ".app")
}

func normalizeAppResult(value string) string {
	value = strings.NewReplacer("\x00", " ", "\r", " ", "\n", " ").Replace(value)
	value = strings.TrimSpace(value)
	for strings.HasSuffix(value, "AppMod finish") {
		value = strings.TrimSpace(strings.TrimSuffix(value, "AppMod finish"))
	}
	if strings.Contains(value, "App install path:") || strings.Contains(value, "App uninstall path:") {
		if index := strings.LastIndex(value, "msg:"); index >= 0 {
			value = strings.TrimSpace(value[index+len("msg:"):])
		}
	}
	return value
}
