// Package gateway 是公网 daemon 入口：为每个授权 Binding 开 TCP listener，握手前做来源/并发/TTL admission，
// 握手后按协议族把帧路由到各 bridge，再经主 HDC target channel 抵达设备。
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/audit"
	"github.com/yabi-zzh/hdc-remote-kit/internal/bridge"
	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/hdc"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/policy"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

// DeviceResolver 把内部 deviceID 解析为当前在线设备的 connectKey，由 remote.Manager 实现。
type DeviceResolver interface {
	ResolveOnlineConnectKey(ctx context.Context, deviceID string) (string, error)
}

// ConnectionObserver 上报每设备 listener 上的连接生命周期事件，由 remote.Manager 实现（gateway 不改租约业务状态，只上报）。
type ConnectionObserver interface {
	ConnectionOpened(leaseID string)
	ConnectionClosed(leaseID string)
	ConnectionRejected(leaseID, reason string)
}

// Gateway 是公网 daemon 入口：为每个已授权 Binding 开一个 TCP listener，握手前做 admission（TTL/来源/并发），
// 握手后按协议族把帧路由到各 bridge，再经主 HDC target channel 抵达设备。每设备一个 listener，连接级并发隔离。
type Gateway struct {
	cfg          config.Config
	resolver     DeviceResolver
	observer     ConnectionObserver
	host         *hdc.HostClient
	codec        *protocol.Codec
	policyEngine *policy.Policy
	recorder     audit.Recorder
	logger       *slog.Logger

	tempStoreOnce sync.Once
	tempStore     *bridge.TempStore
	tempStoreErr  error

	mu        sync.Mutex
	listeners map[string]*listenerState
	closed    bool
	wg        sync.WaitGroup
}

// New 构造 gateway；recorder 可为 nil（不记审计），resolver/observer 通常均为 remote.Manager。
func New(cfg config.Config, resolver DeviceResolver, observer ConnectionObserver, host *hdc.HostClient, recorder audit.Recorder, logger *slog.Logger) *Gateway {
	return &Gateway{
		cfg: cfg, resolver: resolver, observer: observer, host: host,
		codec: protocol.NewCodec(cfg.MaxDaemonFrameBytes), recorder: recorder, logger: logger,
		policyEngine: policy.New(policy.Config{ExtraDeniedExecutables: cfg.ExtraDeniedExecutables}),
		listeners:    make(map[string]*listenerState),
	}
}

// Bind 依据 Grant 为某 Binding 启动 TCP listener 并开始 accept；校验 Grant 完整性、幂等（已存在则跳过）、关闭后拒绝。
// 返回成功即表示端口已在监听，可对外报告为可连接。
func (g *Gateway) Bind(ctx context.Context, grant model.Grant) error {
	binding := grant.Binding
	if binding.ID == "" || binding.DeviceID == "" || binding.Port <= 0 || binding.Port > 65535 ||
		grant.LeaseID == "" || grant.MaxConnections <= 0 || len(grant.AllowedSourcePrefixes) == 0 || grant.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid remote grant")
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return fmt.Errorf("gateway is closed")
	}
	if _, exists := g.listeners[binding.ID]; exists {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	address := net.JoinHostPort(g.cfg.ProxyBindHost, strconv.Itoa(binding.Port))
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("listen remote HDC endpoint %s: %w", address, err)
	}
	state := &listenerState{grant: grant, listener: listener, connections: make(map[net.Conn]struct{})}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = listener.Close()
		return fmt.Errorf("gateway is closed")
	}
	if _, exists := g.listeners[binding.ID]; exists {
		g.mu.Unlock()
		_ = listener.Close()
		return nil
	}
	g.listeners[binding.ID] = state
	g.wg.Add(1)
	g.mu.Unlock()

	go g.acceptLoop(state)
	return nil
}

func (g *Gateway) transferTempStore(root string) (*bridge.TempStore, error) {
	g.tempStoreOnce.Do(func() {
		g.tempStore, g.tempStoreErr = bridge.NewTempStore(root, g.cfg.MaxTempBytes)
	})
	return g.tempStore, g.tempStoreErr
}

// Unbind 停止指定 Binding 的 listener 并关闭其上所有活跃连接；未知 bindingID 视为 no-op。
func (g *Gateway) Unbind(bindingID string) error {
	if strings.TrimSpace(bindingID) == "" {
		return nil
	}
	g.mu.Lock()
	state := g.listeners[bindingID]
	delete(g.listeners, bindingID)
	g.mu.Unlock()
	if state == nil {
		return nil
	}
	state.close()
	g.logger.Info("HDC remote gateway stopped", "binding_id", bindingID)
	return nil
}

// Close 关闭所有 listener 与连接并等待全部 accept/handle goroutine 退出（有序关闭）。
func (g *Gateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	states := make([]*listenerState, 0, len(g.listeners))
	for id, state := range g.listeners {
		states = append(states, state)
		delete(g.listeners, id)
	}
	g.mu.Unlock()

	for _, state := range states {
		state.close()
	}
	g.wg.Wait()
	return nil
}

// acceptLoop 接受某 listener 上的连接，逐个做握手前 admission，通过则起 goroutine 处理，拒绝则上报并关闭。
func (g *Gateway) acceptLoop(state *listenerState) {
	defer g.wg.Done()
	for {
		conn, err := state.listener.Accept()
		if err != nil {
			if !state.isClosed() && !errors.Is(err, net.ErrClosed) {
				g.logger.Warn("HDC remote accept failed", "binding_id", state.grant.Binding.ID, "error", err)
			}
			return
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
		if accepted, reason := state.admit(conn, time.Now().UTC()); !accepted {
			g.logger.Warn("connection rejected",
				"serial", model.DeviceSerial(state.grant.Binding.DeviceID),
				"remote", conn.RemoteAddr().String(),
				"reason", reason)
			if g.observer != nil {
				g.observer.ConnectionRejected(state.grant.LeaseID, reason)
			}
			_ = conn.Close()
			continue
		}
		g.logger.Info("connection accepted",
			"serial", model.DeviceSerial(state.grant.Binding.DeviceID),
			"remote", conn.RemoteAddr().String())
		if g.observer != nil {
			g.observer.ConnectionOpened(state.grant.LeaseID)
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer state.removeConnection(conn)
			if g.observer != nil {
				defer g.observer.ConnectionClosed(state.grant.LeaseID)
			}
			g.handleConnection(state.grant, conn)
		}()
	}
}

// handleConnection 为一条已准入的连接构建 daemonConnection，装配各协议族 bridge（共享同一 target channel 打开闭包），
// 然后进入帧读取-路由主循环直至连接结束。
func (g *Gateway) handleConnection(grant model.Grant, conn net.Conn) {
	binding := grant.Binding
	ctx, cancel := context.WithCancel(context.Background())
	remote := &daemonConnection{
		ctx: ctx, cancel: cancel, conn: conn, binding: binding,
		resolver: g.resolver, host: g.host, codec: g.codec, logger: g.logger,
		recorder:      g.recorder,
		leaseID:       grant.LeaseID,
		ownerID:       grant.OwnerID,
		sourceIP:      sourceIP(conn.RemoteAddr()),
		connectionID:  newConnectionID(),
		shells:        make(map[uint32]*shellSession),
		openChannels:  make(map[uint32]struct{}),
		maxChannels:   g.cfg.MaxChannelsPerConnection,
		policyEngine:  g.policyEngine,
		policyProfile: policy.Profile(grant.PolicyProfile),
	}
	fileTempRoot := filepath.Join(g.cfg.StateDir, "transfers")
	tempStore, err := g.transferTempStore(fileTempRoot)
	if err != nil {
		g.logger.Warn("HDC file bridge unavailable", "serial", model.DeviceSerial(binding.DeviceID), "error", err)
	} else {
		remote.fileBridge = bridge.NewFileBridge(ctx, g.codec, tempStore, g.cfg.MaxFileBytes,
			g.cfg.FileTransferTimeout, func(targetCtx context.Context, command string) (bridge.TargetChannel, error) {
				connectKey, resolveErr := g.resolver.ResolveOnlineConnectKey(targetCtx, binding.DeviceID)
				if resolveErr != nil {
					return nil, resolveErr
				}
				return g.host.OpenTarget(targetCtx, connectKey, command)
			}, remote.write)
	}
	remote.unityBridge = bridge.NewUnityBridge(ctx, g.codec, g.cfg.UnityStreamTimeout,
		func(targetCtx context.Context, command string) (bridge.TargetChannel, error) {
			connectKey, resolveErr := g.resolver.ResolveOnlineConnectKey(targetCtx, binding.DeviceID)
			if resolveErr != nil {
				return nil, resolveErr
			}
			return g.host.OpenTarget(targetCtx, connectKey, command)
		}, remote.write)
	remote.appBridge = bridge.NewAppBridge(ctx, g.codec, tempStore, g.cfg.MaxFileBytes, g.cfg.FileTransferTimeout,
		func(targetCtx context.Context, command string) (bridge.TargetChannel, error) {
			connectKey, resolveErr := g.resolver.ResolveOnlineConnectKey(targetCtx, binding.DeviceID)
			if resolveErr != nil {
				return nil, resolveErr
			}
			return g.host.OpenTarget(targetCtx, connectKey, command)
		}, remote.write)
	remote.forwardBridge = bridge.NewForwardBridge(ctx, g.codec, g.cfg.FileTransferTimeout,
		func(targetCtx context.Context, command string) (bridge.TargetChannel, error) {
			connectKey, resolveErr := g.resolver.ResolveOnlineConnectKey(targetCtx, binding.DeviceID)
			if resolveErr != nil {
				return nil, resolveErr
			}
			return g.host.OpenTarget(targetCtx, connectKey, command)
		}, remote.write)
	remote.forwardBridge.SetLogger(g.logger)

	remote.run()
	g.logger.Info("connection closed",
		"serial", model.DeviceSerial(binding.DeviceID),
		"remote", conn.RemoteAddr().String())
}

type listenerState struct {
	grant    model.Grant
	listener net.Listener

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
}

// admit 是握手前准入判定：租约未过期、来源 IP 在白名单、未超并发上限，通过则原子占用一个并发名额。
func (s *listenerState) admit(conn net.Conn, now time.Time) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, "Remote access is closed."
	}
	if !now.Before(s.grant.ExpiresAt) {
		return false, "Remote access lease has expired."
	}
	address, err := remoteAddress(conn.RemoteAddr())
	if err != nil || !prefixesContain(s.grant.AllowedSourcePrefixes, address) {
		return false, "Source IP is not allowed."
	}
	if len(s.connections) >= s.grant.MaxConnections {
		return false, "Remote access connection limit was reached."
	}
	s.connections[conn] = struct{}{}
	return true, ""
}

func (s *listenerState) removeConnection(conn net.Conn) {
	s.mu.Lock()
	delete(s.connections, conn)
	s.mu.Unlock()
	_ = conn.Close()
}

func remoteAddress(address net.Addr) (netip.Addr, error) {
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		parsed, valid := netip.AddrFromSlice(tcpAddress.IP)
		if !valid {
			return netip.Addr{}, fmt.Errorf("invalid TCP source address")
		}
		return parsed.Unmap(), nil
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}, err
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return parsed.Unmap(), nil
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		candidate := address
		if prefix.Addr().Is4() {
			candidate = address.Unmap()
		}
		if prefix.Contains(candidate) {
			return true
		}
	}
	return false
}

func (s *listenerState) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *listenerState) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	_ = s.listener.Close()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

// daemonConnection 表示一条已准入的 tconn 连接的 daemon 侧会话：持有 codec、各协议族 bridge、
// shell session 表与跨帧输入护栏缓冲，以及审计上下文（lease/owner/sourceIP/connectionID）。
type daemonConnection struct {
	ctx      context.Context
	cancel   context.CancelFunc
	conn     net.Conn
	binding  model.Binding
	resolver DeviceResolver
	host     *hdc.HostClient
	codec    *protocol.Codec
	logger   *slog.Logger

	recorder     audit.Recorder
	leaseID      string
	ownerID      string
	sourceIP     string
	connectionID string

	writeMu           sync.Mutex
	handshakeAccepted bool
	policyEngine      *policy.Policy
	policyProfile     policy.Profile
	channelMu         sync.Mutex
	openChannels      map[uint32]struct{}
	maxChannels       int
	shellMu           sync.Mutex
	shells            map[uint32]*shellSession
	shellInput        map[uint32]*strings.Builder
	fileBridge        *bridge.FileBridge
	unityBridge       *bridge.UnityBridge
	appBridge         *bridge.AppBridge
	forwardBridge     *bridge.ForwardBridge
}

// run 是连接主循环：逐帧读取、解码、路由；协议违规立即回错并终止连接，普通命令失败仅回错不断连。
func (c *daemonConnection) run() {
	defer c.close()
	for {
		rawFrame, err := c.codec.ReadFrame(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				c.logger.Debug("HDC daemon read ended", "serial", model.DeviceSerial(c.binding.DeviceID), "error", err)
			}
			return
		}
		frame, err := c.codec.Decode(rawFrame)
		if err != nil {
			c.logger.Warn("HDC daemon frame rejected", "serial", model.DeviceSerial(c.binding.DeviceID), "error", err)
			return
		}
		if err := c.route(frame); err != nil {
			c.logger.Warn("HDC daemon command failed", "serial", model.DeviceSerial(c.binding.DeviceID), "command", frame.CommandName, "error", err)
			var violation *daemonProtocolViolation
			if errors.As(err, &violation) {
				_ = c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, violation.Error()))
				return
			}
			if writeErr := c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Command execution failed.")); writeErr != nil {
				return
			}
		}
	}
}

type daemonProtocolViolation struct {
	message string
}

func (e *daemonProtocolViolation) Error() string {
	return e.message
}

// shouldLogDaemonFrame 过滤高频噪声帧与已有更具体日志覆盖的帧。
func shouldLogDaemonFrame(flag protocol.Command) bool {
	switch flag {
	case protocol.CommandFileData,
		protocol.CommandShellData,
		protocol.CommandKernelChannelClose,
		protocol.CommandKernelEcho,
		protocol.CommandKernelEchoRaw,
		protocol.CommandKernelEnableKeepalive,
		protocol.CommandKernelWakeupSlaveTask,
		// shell 开通道已由 "HDC shell open" 覆盖，避免 frame+open+host 三条重复。
		protocol.CommandShellInit,
		protocol.CommandUnityExecute,
		protocol.CommandUnityExecuteEx:
		return false
	default:
		return true
	}
}

// route 是帧分发核心：强制先握手、拒绝重复握手、帧级策略黑名单拦截，随后按命令族分派到对应处理器/ bridge；
// 未接入的族回 fail-closed。可审计的命令发起帧在此记 ALLOWED（shell 族在 handleShell 内单独记，避免重复）。
func (c *daemonConnection) route(frame protocol.Frame) error {
	if c.logger != nil && shouldLogDaemonFrame(frame.CommandFlag) {
		c.logger.Debug("HDC daemon frame",
			"serial", model.DeviceSerial(c.binding.DeviceID),
			"channel_id", frame.ChannelID,
			"command", frame.CommandName,
			"payload_bytes", len(frame.Payload))
	}
	if !c.handshakeAccepted && frame.CommandFlag != protocol.CommandKernelHandshake {
		c.audit(frame, model.AuditRejected, "handshake required")
		return &daemonProtocolViolation{message: "HDC daemon handshake is required."}
	}
	if c.handshakeAccepted && frame.CommandFlag == protocol.CommandKernelHandshake {
		c.audit(frame, model.AuditRejected, "handshake already complete")
		return &daemonProtocolViolation{message: "HDC daemon handshake is already complete."}
	}
	if decision := c.policyOrDefault().InspectFrame(frame.CommandFlag); !decision.Allowed {
		if c.logger != nil {
			c.logger.Debug("HDC daemon frame denied by policy",
				"serial", model.DeviceSerial(c.binding.DeviceID), "command", frame.CommandName, "rule", decision.Rule)
		}
		c.audit(frame, model.AuditRejected, decision.Rule)
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, decision.Reason))
	}
	if !c.admitChannel(frame.CommandFlag, frame.ChannelID) {
		c.audit(frame, model.AuditRejected, "channel limit reached")
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Too many concurrent channels for this connection."))
	}
	if auditableCommand(frame.CommandFlag) {
		c.audit(frame, model.AuditAllowed, "")
	}
	switch protocol.CommandFamily(frame.CommandFlag) {
	case protocol.FamilyKernel:
		return c.handleKernel(frame)
	case protocol.FamilyShell:
		return c.handleShell(frame)
	case protocol.FamilyFile:
		if c.fileBridge == nil {
			return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "File transfer is unavailable."))
		}
		return c.fileBridge.Handle(frame)
	case protocol.FamilyUnity:
		if c.unityBridge == nil {
			return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Unity command is unavailable."))
		}
		return c.unityBridge.Handle(frame)
	case protocol.FamilyApp:
		if c.appBridge != nil {
			return c.appBridge.Handle(frame)
		}
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "App command is unavailable."))
	case protocol.FamilyForward:
		if c.forwardBridge == nil {
			return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Forward command is unavailable."))
		}
		return c.forwardBridge.Handle(frame)
	default:
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Command is not supported."))
	}
}

// handleKernel 处理内核族：完成握手鉴权、响应 keepalive/echo/checkserver 等存活帧、处理 ChannelClose 并清理各 bridge 通道。
func (c *daemonConnection) handleKernel(frame protocol.Frame) error {
	switch frame.CommandFlag {
	case protocol.CommandKernelHandshake:
		handshake, err := c.codec.DecodeSessionHandshake(frame.Payload)
		if err != nil || handshake.Banner != "OHOS HDC" || handshake.AuthType != protocol.HandshakeAuthNone {
			c.audit(frame, model.AuditRejected, "invalid handshake")
			return &daemonProtocolViolation{message: "Invalid HDC daemon handshake."}
		}
		c.audit(frame, model.AuditAllowed, "")
		c.handshakeAccepted = true
		if c.logger != nil {
			c.logger.Debug("HDC daemon handshake accepted", "serial", model.DeviceSerial(c.binding.DeviceID), "remote", c.sourceIP)
		}
		response := c.codec.EncodeHandshakeOK(frame, handshake, c.binding.DeviceID)
		response = append(response, c.codec.EncodeChannelClose(frame.ChannelID)...)
		return c.write(response)
	case protocol.CommandKernelChannelClose:
		c.untrackChannel(frame.ChannelID)
		c.stopShell(frame.ChannelID, true)
		if c.fileBridge != nil {
			c.fileBridge.CloseChannel(frame.ChannelID)
		}
		if c.unityBridge != nil {
			c.unityBridge.CloseChannel(frame.ChannelID)
		}
		if c.appBridge != nil {
			c.appBridge.CloseChannel(frame.ChannelID)
		}
		if c.forwardBridge != nil {
			c.forwardBridge.CloseChannel(frame.ChannelID)
		}
		return c.write(c.codec.EncodeChannelCloseResponse(frame.ChannelID, frame.Payload))
	case protocol.CommandKernelEcho, protocol.CommandKernelEchoRaw, protocol.CommandKernelEnableKeepalive,
		protocol.CommandKernelWakeupSlaveTask, protocol.CommandCheckServer, protocol.CommandCheckDevice, protocol.CommandWaitFor:
		return c.write(c.codec.EncodeEchoRaw(frame.ChannelID, nil))
	default:
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Command is not supported."))
	}
}

// handleShell 处理 shell 族：ShellInit 开交互式 shell、ShellData 转发 stdin、UnityExecute(Ex) 一次性命令或交互输入；
// 所有命令与交互输入先过 policy（交互 stdin 用跨帧累积护栏），拒绝则关会话并回错。
func (c *daemonConnection) handleShell(frame protocol.Frame) error {
	switch frame.CommandFlag {
	case protocol.CommandShellInit:
		c.audit(frame, model.AuditAllowed, "")
		return c.openShell(frame.ChannelID, "")
	case protocol.CommandShellData:
		session := c.getShell(frame.ChannelID)
		if session == nil {
			return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Shell session is not available."))
		}
		// 交互式 stdin 按 channel 累积再检查，识别被拆到多帧的高危命令。
		guarded := c.appendShellInput(frame.ChannelID, frame.Payload)
		if decision := c.policyOrDefault().InspectShell(c.policyProfile, guarded); !decision.Allowed {
			c.audit(frame, model.AuditRejected, decision.Rule)
			c.stopShell(frame.ChannelID, true)
			return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, decision.Reason))
		}
		return session.target.WritePayload(frame.Payload)
	case protocol.CommandUnityExecute, protocol.CommandUnityExecuteEx:
		command := protocol.ExtractShellCommand(frame)
		if session := c.getShell(frame.ChannelID); session != nil {
			if command == "" {
				return nil
			}
			// 已有交互 session 时，UnityExecute 视作 stdin，同样累积跨帧检查。
			guarded := c.appendShellInput(frame.ChannelID, []byte(command))
			if decision := c.policyOrDefault().InspectShell(c.policyProfile, guarded); !decision.Allowed {
				c.audit(frame, model.AuditRejected, decision.Rule)
				c.stopShell(frame.ChannelID, true)
				return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, decision.Reason))
			}
			c.audit(frame, model.AuditAllowed, "")
			return session.target.WritePayload([]byte(command))
		}
		if decision := c.policyOrDefault().InspectShell(c.policyProfile, command); !decision.Allowed {
			c.audit(frame, model.AuditRejected, decision.Rule)
			return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, decision.Reason))
		}
		c.audit(frame, model.AuditAllowed, "")
		return c.openShell(frame.ChannelID, command)
	default:
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "Command is not supported."))
	}
}

// openShell 解析在线 connectKey、经主 HDC 打开 shell target channel 并起读循环把设备输出回推 client；
// command 为空表示交互式，否则一次性命令。
func (c *daemonConnection) openShell(channelID uint32, command string) error {
	if c.getShell(channelID) != nil {
		return nil
	}
	if decision := c.policyOrDefault().InspectShell(c.policyProfile, command); !decision.Allowed {
		if c.logger != nil {
			c.logger.Debug("HDC shell denied by policy",
				"serial", model.DeviceSerial(c.binding.DeviceID), "rule", decision.Rule)
		}
		return c.write(c.codec.EncodeEchoAndClose(channelID, decision.Reason))
	}
	connectKey, err := c.resolver.ResolveOnlineConnectKey(c.ctx, c.binding.DeviceID)
	if err != nil {
		return fmt.Errorf("resolve target device: %w", err)
	}
	initCommand := "shell"
	if strings.TrimSpace(command) != "" {
		initCommand += " " + strings.TrimSpace(command)
	}
	if c.logger != nil {
		mode := "interactive"
		if strings.TrimSpace(command) != "" {
			mode = "oneshot"
		}
		c.logger.Debug("HDC shell open",
			"serial", model.DeviceSerial(c.binding.DeviceID),
			"mode", mode,
			"command_head", firstToken(command))
	}
	target, err := c.host.OpenTarget(c.ctx, connectKey, initCommand)
	if err != nil {
		return fmt.Errorf("open target shell: %w", err)
	}
	session := &shellSession{channelID: channelID, target: target, owner: c}
	c.shellMu.Lock()
	if _, exists := c.shells[channelID]; exists {
		c.shellMu.Unlock()
		_ = target.Close()
		return nil
	}
	c.shells[channelID] = session
	c.shellMu.Unlock()
	go session.readLoop()
	return nil
}

func firstToken(command string) string {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func (c *daemonConnection) getShell(channelID uint32) *shellSession {
	c.shellMu.Lock()
	defer c.shellMu.Unlock()
	return c.shells[channelID]
}

// shellInputGuardLimit 是交互式 shell 输入护栏的滑动窗口上限（字节）。
const shellInputGuardLimit = 4096

// appendShellInput 按 channel 累积交互式 stdin 并返回窗口内累积文本，
// 用于识别被拆到多帧发送的高危命令。
func (c *daemonConnection) appendShellInput(channelID uint32, chunk []byte) string {
	c.shellMu.Lock()
	defer c.shellMu.Unlock()
	if c.shellInput == nil {
		c.shellInput = make(map[uint32]*strings.Builder)
	}
	buffer := c.shellInput[channelID]
	if buffer == nil {
		buffer = &strings.Builder{}
		c.shellInput[channelID] = buffer
	}
	buffer.WriteString(string(chunk))
	if buffer.Len() > shellInputGuardLimit {
		// 只保留最近的窗口，避免长交互 session 无界增长，同时仍能识别跨帧拼接的命令。
		trimmed := buffer.String()[buffer.Len()-shellInputGuardLimit:]
		buffer.Reset()
		buffer.WriteString(trimmed)
	}
	return buffer.String()
}

func (c *daemonConnection) stopShell(channelID uint32, byUs bool) {
	c.shellMu.Lock()
	session := c.shells[channelID]
	delete(c.shells, channelID)
	delete(c.shellInput, channelID)
	c.shellMu.Unlock()
	if session != nil {
		session.close(byUs)
	}
}

func (c *daemonConnection) removeShell(channelID uint32, session *shellSession) {
	c.shellMu.Lock()
	if c.shells[channelID] == session {
		delete(c.shells, channelID)
		delete(c.shellInput, channelID)
	}
	c.shellMu.Unlock()
}

// policyOrDefault 返回连接的命令策略实例；未注入时回退默认策略（供单测直接构造连接的场景）。
func (c *daemonConnection) policyOrDefault() *policy.Policy {
	if c.policyEngine != nil {
		return c.policyEngine
	}
	return policy.Default()
}

// admitChannel 是每连接 channel 数护栏：握手与关闭帧直接放行；其余帧首次引用某 channelID 时占用一个名额，
// 超过 maxChannels 即拒绝，防止单条 tconn 连接无限开 channel 放大资源占用。已登记的 channelID 始终放行。
// maxChannels<=0 表示不限制（仅用于单测直接构造连接的场景）。
func (c *daemonConnection) admitChannel(flag protocol.Command, channelID uint32) bool {
	if flag == protocol.CommandKernelHandshake || flag == protocol.CommandKernelChannelClose {
		return true
	}
	c.channelMu.Lock()
	defer c.channelMu.Unlock()
	if c.openChannels == nil {
		c.openChannels = make(map[uint32]struct{})
	}
	if _, exists := c.openChannels[channelID]; exists {
		return true
	}
	if c.maxChannels > 0 && len(c.openChannels) >= c.maxChannels {
		return false
	}
	c.openChannels[channelID] = struct{}{}
	return true
}

// untrackChannel 在 channel 关闭时释放其占用的名额。
func (c *daemonConnection) untrackChannel(channelID uint32) {
	c.channelMu.Lock()
	delete(c.openChannels, channelID)
	c.channelMu.Unlock()
}

func (c *daemonConnection) write(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(payload); err != nil {
		return fmt.Errorf("write HDC daemon response: %w", err)
	}
	return nil
}

func (c *daemonConnection) close() {
	c.cancel()
	if c.fileBridge != nil {
		c.fileBridge.Close()
	}
	if c.unityBridge != nil {
		c.unityBridge.Close()
	}
	if c.appBridge != nil {
		c.appBridge.Close()
	}
	if c.forwardBridge != nil {
		c.forwardBridge.Close()
	}
	c.shellMu.Lock()
	sessions := make([]*shellSession, 0, len(c.shells))
	for _, session := range c.shells {
		sessions = append(sessions, session)
	}
	c.shells = make(map[uint32]*shellSession)
	c.shellMu.Unlock()
	for _, session := range sessions {
		session.close(true)
	}
	_ = c.conn.Close()
}

type shellSession struct {
	channelID uint32
	target    *hdc.TargetChannel
	owner     *daemonConnection

	closeOnce  sync.Once
	mu         sync.Mutex
	closedByUs bool
}

func (s *shellSession) readLoop() {
	defer func() {
		s.owner.removeShell(s.channelID, s)
		s.mu.Lock()
		closedByUs := s.closedByUs
		s.mu.Unlock()
		// 仅当设备侧 shell 自行结束（一次性命令完成或交互退出）时通知客户端关闭通道；
		// 我方主动关闭（客户端已关或连接拆除）不重复下发。
		if !closedByUs {
			_ = s.owner.write(s.owner.codec.EncodeChannelClose(s.channelID))
		}
		s.closeOnce.Do(func() { _ = s.target.Close() })
	}()
	for {
		payload, err := s.target.ReadPayload()
		if err != nil {
			return
		}
		if len(payload) > 0 {
			if err := s.owner.write(s.owner.codec.EncodeEchoRaw(s.channelID, payload)); err != nil {
				return
			}
		}
	}
}

func (s *shellSession) close(byUs bool) {
	if byUs {
		s.mu.Lock()
		s.closedByUs = true
		s.mu.Unlock()
	}
	s.closeOnce.Do(func() { _ = s.target.Close() })
}
