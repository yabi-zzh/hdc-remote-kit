// Package hdc 是连接服务器本机主 HDC server 的 client-channel 客户端：
// 拉取 target 列表完成设备发现，并按 connectKey 为设备打开命令 target channel，不做设备拓扑变更。
package hdc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

const (
	channelHandshakeMinBytes = 44
	channelHandshakeKeyStart = 12
	channelHandshakeKeyBytes = 32
)

// HostClient 是本服务连接服务器本机主 HDC server 的 client-channel 客户端。
// 它只做两件事：拉取 target 列表（设备发现），以及按 connectKey 为某设备打开一条命令 target channel。
// 主 HDC server 与 USB 设备的会话始终由主 server 管理，本客户端不做拓扑变更。
type HostClient struct {
	addr            string
	connectTimeout  time.Duration
	readTimeout     time.Duration
	maxPayloadBytes int
	serverNode      string
	logger          *slog.Logger
}

// NewHostClient 依据配置构造主 HDC server 客户端（地址、连接/读超时、负载上限、节点标识）。
func NewHostClient(cfg config.Config, logger *slog.Logger) *HostClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &HostClient{
		addr:            cfg.HDCAddr,
		connectTimeout:  cfg.HostConnectTimeout,
		readTimeout:     cfg.HostReadTimeout,
		maxPayloadBytes: cfg.MaxHostPayloadBytes,
		serverNode:      cfg.ServerNode,
		logger:          logger,
	}
}

// ListTargets 执行 `list targets -v` 并解析出全量 target 事实快照（含 USB/TCP、在线状态、型号）。
func (h *HostClient) ListTargets(ctx context.Context) ([]model.Device, error) {
	payload, err := h.sendCommand(ctx, "list targets -v", "")
	if err != nil {
		return nil, fmt.Errorf("list HDC targets: %w", err)
	}
	devices := parseTargets(payload, h.serverNode)
	return devices, nil
}

// OpenTarget 为指定 connectKey 的设备打开一条命令 target channel：
// 完成 channel 握手、写入命令并清除读超时（命令可能长时间流式输出），返回可读写的 TargetChannel。
// 返回后连接的生命周期由调用方（bridge）负责。
func (h *HostClient) OpenTarget(ctx context.Context, connectKey, command string) (*TargetChannel, error) {
	if strings.TrimSpace(connectKey) == "" {
		return nil, fmt.Errorf("HDC connect key is required")
	}
	if strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("HDC target command is required")
	}
	h.logger.Debug("HDC host open target", "serial", connectKey, "command_head", commandHead(command))
	conn, err := h.openChannel(ctx, connectKey)
	if err != nil {
		return nil, err
	}
	if err := writeChannelFrame(conn, []byte(command+"\x00")); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write HDC target command: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear HDC target deadline: %w", err)
	}
	return NewTargetChannel(conn, h.maxPayloadBytes), nil
}

func (h *HostClient) sendCommand(ctx context.Context, command, connectKey string) ([]byte, error) {
	conn, err := h.openChannel(ctx, connectKey)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := writeChannelFrame(conn, []byte(command+"\x00")); err != nil {
		return nil, fmt.Errorf("write HDC command: %w", err)
	}
	payload, err := readChannelFrame(conn, h.maxPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("read HDC command response: %w", err)
	}
	if strings.HasPrefix(string(payload), "[Fail]") {
		return nil, fmt.Errorf("HDC command failed: %s", strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

// openChannel 建立到主 HDC server 的一条 client-channel：拨号、读服务端握手帧、回写带 connectKey 的握手帧。
// connectKey 为空表示会话级命令（如 list targets），非空表示定位具体设备。
func (h *HostClient) openChannel(ctx context.Context, connectKey string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, h.connectTimeout)
	defer cancel()
	// 开启 keepalive：OpenTarget 会为流式命令永久清除读写 deadline，
	// 主 HDC 若未发 FIN 就消失（进程被杀、主机休眠），读循环会永远阻塞并占住 fd。
	conn, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(dialCtx, "tcp", h.addr)
	if err != nil {
		return nil, fmt.Errorf("connect HDC host %s: %w", h.addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(h.readTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set HDC deadline: %w", err)
	}
	serverHandshake, err := readChannelFrame(conn, h.maxPayloadBytes)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read HDC handshake: %w", err)
	}
	clientHandshake, err := buildClientHandshake(serverHandshake, connectKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("build HDC handshake: %w", err)
	}
	if err := writeChannelFrame(conn, clientHandshake); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write HDC handshake: %w", err)
	}
	return conn, nil
}

func readChannelFrame(reader io.Reader, maxPayloadBytes int) ([]byte, error) {
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if uint64(length) > uint64(maxPayloadBytes) {
		return nil, fmt.Errorf("HDC channel payload exceeds limit: %d", length)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeChannelFrame(writer io.Writer, payload []byte) error {
	if len(payload) > int(^uint32(0)) {
		return fmt.Errorf("HDC channel payload is too large: %d", len(payload))
	}
	var lengthBytes [4]byte
	binary.BigEndian.PutUint32(lengthBytes[:], uint32(len(payload)))
	if _, err := writer.Write(lengthBytes[:]); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

// buildClientHandshake 基于服务端握手帧构造客户端应答：校验 banner，
// 把握手帧固定偏移处的 connectKey 字段清零后写入目标 connectKey，据此让主 HDC server 把该 channel 绑定到指定设备。
func buildClientHandshake(serverHandshake []byte, connectKey string) ([]byte, error) {
	if len(serverHandshake) < channelHandshakeMinBytes {
		return nil, fmt.Errorf("HDC channel handshake is too short: %d", len(serverHandshake))
	}
	if string(serverHandshake[:8]) != "OHOS HDC" {
		return nil, fmt.Errorf("HDC channel handshake banner mismatch")
	}
	clientHandshake := append([]byte(nil), serverHandshake...)
	for i := channelHandshakeKeyStart; i < channelHandshakeKeyStart+channelHandshakeKeyBytes; i++ {
		clientHandshake[i] = 0
	}
	keyBytes := []byte(connectKey)
	if len(keyBytes) > channelHandshakeKeyBytes {
		keyBytes = keyBytes[:channelHandshakeKeyBytes]
	}
	copy(clientHandshake[channelHandshakeKeyStart:], keyBytes)
	return clientHandshake, nil
}

// parseTargets 解析 `list targets -v` 的多行输出，逐行提取 connectKey、连接类型、状态与型号，
// 过滤 [Empty]/[Info]/[Fail] 等非设备行，生成设备事实列表。
func parseTargets(raw []byte, serverNode string) []model.Device {
	var devices []model.Device
	for _, rawLine := range strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || line == "[Empty]" || strings.HasPrefix(line, "[Info]") || strings.HasPrefix(line, "[Fail]") {
			continue
		}
		fields := strings.Split(rawLine, "\t")
		connectKey := strings.TrimSpace(fields[0])
		if connectKey == "" {
			continue
		}
		transport, status := classifyTarget(fields, line)
		modelName := targetModel(fields, transport, status)
		devices = append(devices, model.Device{
			ID:         scopedID(serverNode, connectKey),
			ConnectKey: connectKey,
			Transport:  transport,
			Status:     status,
			Model:      modelName,
			ServerNode: serverNode,
			UpdatedAt:  time.Now(),
		})
	}
	return devices
}

func classifyTarget(fields []string, line string) (model.Transport, model.TargetStatus) {
	transport := model.TransportUnknown
	status := model.TargetUnknown
	for _, field := range fields {
		normalized := strings.ToLower(strings.TrimSpace(field))
		switch normalized {
		case "usb":
			transport = model.TransportUSB
		case "tcp", "tcpip":
			transport = model.TransportTCP
		case "online", "connected":
			status = model.TargetOnline
		case "offline", "disconnected":
			status = model.TargetOffline
		case "unauthorized":
			status = model.TargetUnauthorized
		}
	}
	lowerLine := strings.ToLower(line)
	if status == model.TargetUnknown {
		switch {
		case strings.Contains(lowerLine, "unauthorized"):
			status = model.TargetUnauthorized
		case strings.Contains(lowerLine, "offline") || strings.Contains(lowerLine, "disconnect"):
			status = model.TargetOffline
		case len(fields) == 1:
			status = model.TargetOnline
		}
	}
	if transport == model.TransportUnknown {
		switch {
		case strings.Contains(lowerLine, "usb"):
			transport = model.TransportUSB
		case strings.Contains(lowerLine, "tcp"):
			transport = model.TransportTCP
		}
	}
	return transport, status
}

func targetModel(fields []string, transport model.Transport, status model.TargetStatus) string {
	for _, field := range fields[1:] {
		value := strings.TrimSpace(field)
		normalized := strings.ToLower(value)
		if value == "" || strings.EqualFold(value, string(transport)) || strings.EqualFold(value, string(status)) ||
			normalized == "connected" || normalized == "disconnected" || normalized == "unauthorized" ||
			strings.EqualFold(value, "hdc") {
			continue
		}
		return value
	}
	return ""
}

// scopedID 生成本服务内部稳定设备 ID：`serverNode:connectKey`，两段各自规范化为安全字符集。
// 当前以 connectKey 作用域（在真机上通常即设备序列号）。
func scopedID(serverNode, rawID string) string {
	normalize := func(value string) string {
		value = strings.TrimSpace(value)
		if value == "" {
			return "unknown"
		}
		var builder strings.Builder
		for _, r := range value {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
				builder.WriteRune(r)
			} else {
				builder.WriteByte('-')
			}
		}
		if builder.Len() == 0 {
			return "unknown"
		}
		return builder.String()
	}
	return normalize(serverNode) + ":" + normalize(rawID)
}

// commandHead 只保留命令首个 token，避免 debug 日志泄露完整命令行参数。
func commandHead(command string) string {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
