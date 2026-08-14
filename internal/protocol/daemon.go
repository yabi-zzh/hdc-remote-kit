// Package protocol 实现 HDC daemon 帧与传输结构的编解码、命令目录与协议族归类。
// 所有解析均带严格边界检查（帧长上限、varint/TLV 越界、校验和），防止畸形输入放大内存。
package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// HDC daemon 帧的协议常量。帧结构：11 字节头（"HW" 魔数 + 版本 + protect/payload 长度）+ protect（protobuf 编码的 channelId/command/checksum/vcode）+ payload。
const (
	DaemonHeaderBytes          = 11   // 固定帧头长度
	DaemonProtocolVersion      = 0x01 // 帧头版本字节
	DaemonVCode                = 0x09 // protect 段校验码，解码时严格比对
	HandshakeAuthNone          = 0    // 握手第一轮：客户端声明能力，尚未提交公钥
	HandshakeAuthSignature     = 2    // 握手：签名挑战 / 应答
	HandshakeAuthPublicKey     = 3    // 握手：索要或提交主机公钥
	HandshakeAuthOK            = 4    // 握手应答：鉴权通过（或带 UNAUTH 状态的通知）
	HandshakeAuthFail          = 5
	HandshakeFallbackVersion   = "Ver: 3.2.0c"
	HandshakeMinAuthVersion    = "Ver: 3.0.0b"
	DaemonAuthSuccess          = "SUCCESS"
	DaemonAuthUnauthorized     = "DAEMON_UNAUTH"
	HandshakeTLVAuthType       = "authtype"
	HandshakeAuthTypeSHA512    = "1"
	ChannelCloseRemainingCount = 1 // ChannelClose 帧的初始剩余计数（两段关闭握手用）
)

// Frame 是一个已解码的 HDC daemon 协议帧。
// Payload 指向 Decode 入参的底层数组，不额外复制；调用方若需在本帧处理结束后继续持有，须自行复制。
// ReadFrame 每次返回独立缓冲，故按「读一帧 → 解一帧 → 处理完」的常规流程使用是安全的。
type Frame struct {
	ChannelID   uint32  // 逻辑通道 ID，一条 tconn 连接上多路复用
	CommandFlag Command // 命令码
	CommandName string  // 命令码对应的可读名（未知则为 Unknown(n)）
	CheckSum    uint8
	VCode       uint8
	Payload     []byte // 命令负载
}

// SessionHandshake 是 HDC 会话握手帧的字段集（protobuf 风格编码）。
type SessionHandshake struct {
	Banner     string // 固定 "OHOS HDC"
	AuthType   uint8  // HandshakeAuthNone / PublicKey / Signature / OK
	SessionID  uint32
	ConnectKey string
	Buffer     string // 认证成功时携带 devname 等 TLV
	Version    string
}

// Codec 负责 HDC daemon 帧的读取、编解码；maxFrameBytes 限制单帧大小以防内存放大攻击。
type Codec struct {
	maxFrameBytes int
}

// NewCodec 构造一个限制单帧最大字节数的编解码器。
func NewCodec(maxFrameBytes int) *Codec {
	return &Codec{maxFrameBytes: maxFrameBytes}
}

// ReadFrame 从流中读取一个完整帧的原始字节：先读定长头得到 protect/payload 长度，再读齐帧体；超过 maxFrameBytes 直接拒绝。
func (c *Codec) ReadFrame(reader io.Reader) ([]byte, error) {
	if c.maxFrameBytes <= DaemonHeaderBytes {
		return nil, fmt.Errorf("HDC daemon maximum frame size is too small: %d", c.maxFrameBytes)
	}
	header := make([]byte, DaemonHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	protectSize, payloadSize, err := decodeFrameHeader(header)
	if err != nil {
		return nil, err
	}
	bodySize := uint64(protectSize) + uint64(payloadSize)
	if bodySize > uint64(c.maxFrameBytes-DaemonHeaderBytes) {
		return nil, fmt.Errorf("HDC daemon frame size is invalid: %d", bodySize)
	}
	// 一次分配出整帧再分段读入：header 容量恰好等于帧头长度，
	// append(header, body...) 必然再分配一块并复制两次。
	frame := make([]byte, DaemonHeaderBytes+int(bodySize))
	copy(frame, header)
	if _, err := io.ReadFull(reader, frame[DaemonHeaderBytes:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// Decode 将 ReadFrame 得到的原始字节解析为 Frame：校验帧头、protect 段 vcode 与 payload 校验和，映射命令名。
func (c *Codec) Decode(raw []byte) (Frame, error) {
	if len(raw) < DaemonHeaderBytes || len(raw) > c.maxFrameBytes {
		return Frame{}, fmt.Errorf("invalid HDC daemon frame size")
	}
	protectSize, payloadSize, err := decodeFrameHeader(raw[:DaemonHeaderBytes])
	if err != nil {
		return Frame{}, err
	}
	// 用 uint64 比较：32 位平台上 int(payloadSize) 会溢出成负数，
	// 精心构造的长度字段可借此通过校验并让后面的切片越界。
	if uint64(DaemonHeaderBytes)+uint64(protectSize)+uint64(payloadSize) != uint64(len(raw)) {
		return Frame{}, fmt.Errorf("invalid HDC daemon frame size")
	}
	protect, err := decodeProtect(raw[DaemonHeaderBytes : DaemonHeaderBytes+int(protectSize)])
	if err != nil {
		return Frame{}, err
	}
	if protect.VCode != DaemonVCode {
		return Frame{}, fmt.Errorf("unsupported HDC daemon vcode: %d", protect.VCode)
	}
	payload := raw[DaemonHeaderBytes+int(protectSize):]
	if protect.CheckSum != 0 && protect.CheckSum != payloadChecksum(payload) {
		return Frame{}, fmt.Errorf("invalid HDC daemon payload checksum")
	}
	descriptor, ok := LookupCommand(protect.CommandFlag)
	name := fmt.Sprintf("Unknown(%d)", protect.CommandFlag)
	if ok {
		name = descriptor.Name
	}
	return Frame{
		ChannelID:   protect.ChannelID,
		CommandFlag: protect.CommandFlag,
		CommandName: name,
		CheckSum:    protect.CheckSum,
		VCode:       protect.VCode,
		Payload:     payload,
	}, nil
}

// EncodeFrame 按 HDC daemon 帧格式编码一帧：拼装帧头、protect 段与 payload。是所有 Encode* 的底层。
func (c *Codec) EncodeFrame(channelID uint32, commandFlag Command, payload []byte) []byte {
	protect := encodeProtect(channelID, commandFlag, 0)
	header := make([]byte, DaemonHeaderBytes)
	header[0], header[1], header[4] = 'H', 'W', DaemonProtocolVersion
	binary.BigEndian.PutUint16(header[5:7], uint16(len(protect)))
	binary.BigEndian.PutUint32(header[7:11], uint32(len(payload)))
	result := make([]byte, 0, len(header)+len(protect)+len(payload))
	result = append(result, header...)
	result = append(result, protect...)
	return append(result, payload...)
}

// EncodeEchoRaw 以 CMD_KERNEL_ECHO_RAW 回推设备输出/文本给用户 client（shell、hilog、jpid 等的标准输出通道）。
func (c *Codec) EncodeEchoRaw(channelID uint32, payload []byte) []byte {
	return c.EncodeFrame(channelID, CommandKernelEchoRaw, payload)
}

// EncodeChannelClose 主动通知 client 关闭指定通道（携带初始剩余计数）。
func (c *Codec) EncodeChannelClose(channelID uint32) []byte {
	return c.EncodeFrame(channelID, CommandKernelChannelClose, []byte{ChannelCloseRemainingCount})
}

// EncodeChannelCloseResponse 应答 client 的 ChannelClose：把剩余计数减 1 回发，计数归零则不再回应，完成两段关闭握手。
func (c *Codec) EncodeChannelCloseResponse(channelID uint32, requestPayload []byte) []byte {
	if len(requestPayload) == 0 || requestPayload[0] == 0 {
		return nil
	}
	return c.EncodeFrame(channelID, CommandKernelChannelClose, []byte{requestPayload[0] - 1})
}

// EncodeEchoAndClose 向 client 回一条 [Fail] 前缀的错误文本并紧接一帧 ChannelClose，用于拒绝/失败场景的统一收尾。
func (c *Codec) EncodeEchoAndClose(channelID uint32, message string) []byte {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "[Fail] Command is not supported."
	}
	if !strings.HasPrefix(message, "[Fail]") {
		message = "[Fail] " + message
	}
	result := c.EncodeEchoRaw(channelID, []byte(message+"\n"))
	return append(result, c.EncodeChannelClose(channelID)...)
}

// DecodeSessionHandshake 解析握手帧的 protobuf 风格字段（banner/authType/sessionId/connectKey/buffer/version）。
func (c *Codec) DecodeSessionHandshake(payload []byte) (SessionHandshake, error) {
	cursor := newCursor(payload)
	var handshake SessionHandshake
	for cursor.remaining() {
		key, err := cursor.varint()
		if err != nil {
			return SessionHandshake{}, err
		}
		field, wire := int(key>>3), int(key&7)
		switch field {
		case 1:
			handshake.Banner, err = cursor.stringValue(wire)
		case 2:
			value, readErr := cursor.varintValue(wire)
			if readErr != nil {
				err = readErr
			} else if value > uint64(^uint8(0)) {
				err = fmt.Errorf("HDC handshake auth type is out of range: %d", value)
			} else {
				handshake.AuthType = uint8(value)
			}
		case 3:
			value, readErr := cursor.varintValue(wire)
			if readErr != nil {
				err = readErr
			} else if value > uint64(^uint32(0)) {
				err = fmt.Errorf("HDC handshake session ID is out of range: %d", value)
			} else {
				handshake.SessionID = uint32(value)
			}
		case 4:
			handshake.ConnectKey, err = cursor.stringValue(wire)
		case 5:
			handshake.Buffer, err = cursor.stringValue(wire)
		case 6:
			handshake.Version, err = cursor.stringValue(wire)
		default:
			err = cursor.skip(wire)
		}
		if err != nil {
			return SessionHandshake{}, err
		}
	}
	return handshake, nil
}

// EncodeSessionHandshake 编码一个握手帧（主要供测试与握手请求构造）。
func (c *Codec) EncodeSessionHandshake(channelID uint32, handshake SessionHandshake) []byte {
	return c.EncodeFrame(channelID, CommandKernelHandshake, encodeSessionHandshake(handshake))
}

// EncodeHandshakeOK 构造 daemon 侧握手成功应答：banner=OHOS HDC、authType=OK，buffer 内含设备名等认证成功 TLV。
func (c *Codec) EncodeHandshakeOK(request Frame, requestHandshake SessionHandshake, deviceName string) []byte {
	return c.EncodeHandshakeReply(request.ChannelID, handshakeVersion(requestHandshake.Version), HandshakeAuthOK, buildAuthStatusTLV(deviceName, "", DaemonAuthSuccess))
}

// EncodeHandshakePublicKey 回复 AUTH_PUBLICKEY：若对端支持 SHA-512 则在 buffer 声明 authtype=1。
func (c *Codec) EncodeHandshakePublicKey(channelID uint32, version string, supportSHA512 bool) []byte {
	buffer := ""
	if supportSHA512 {
		buffer = AppendHandshakeTLV("", HandshakeTLVAuthType, HandshakeAuthTypeSHA512)
	}
	return c.EncodeHandshakeReply(channelID, handshakeVersion(version), HandshakeAuthPublicKey, buffer)
}

// EncodeHandshakeSignatureChallenge 发送待签名的随机 token。
func (c *Codec) EncodeHandshakeSignatureChallenge(channelID uint32, version, token string) []byte {
	return c.EncodeHandshakeReply(channelID, handshakeVersion(version), HandshakeAuthSignature, token)
}

// EncodeHandshakeUnauthorized 回 AUTH_OK + DAEMON_UNAUTH：tconn 打印 Connect OK，list targets 为 Unauthorized。
// 用于待确认（会话继续等放行）以及拒绝 / 版本过低（调用方随后拆连接）。
func (c *Codec) EncodeHandshakeUnauthorized(channelID uint32, version, deviceName, message string) []byte {
	reply := c.EncodeHandshakeReply(channelID, handshakeVersion(version), HandshakeAuthOK, buildAuthStatusTLV(deviceName, message, DaemonAuthUnauthorized))
	return append(reply, c.EncodeChannelClose(channelID)...)
}

// EncodeHandshakeReply 编码一帧握手应答，不附带 ChannelClose。
func (c *Codec) EncodeHandshakeReply(channelID uint32, version string, authType uint8, buffer string) []byte {
	response := SessionHandshake{
		Banner:   "OHOS HDC",
		AuthType: authType,
		Buffer:   buffer,
		Version:  handshakeVersion(version),
	}
	return c.EncodeFrame(channelID, CommandKernelHandshake, encodeSessionHandshake(response))
}

func handshakeVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return HandshakeFallbackVersion
	}
	return version
}

type hdcVersion struct {
	major, minor, patch int
	letter              byte
}

// ClientVersionTooOld 判定官方 hdc 版本低于可走公钥握手的下限。
// 按 Ver: <major>.<minor>.<patch><letter> 比较；-buildhash 丢掉。空版本或解不出的版本不拒。
func ClientVersionTooOld(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	got, ok := parseHdcVersion(version)
	if !ok {
		return false
	}
	min, ok := parseHdcVersion(HandshakeMinAuthVersion)
	if !ok {
		return false
	}
	return compareHdcVersion(got, min) < 0
}

func parseHdcVersion(raw string) (hdcVersion, bool) {
	value := strings.TrimSpace(raw)
	if after, ok := strings.CutPrefix(value, "Ver:"); ok {
		value = strings.TrimSpace(after)
	} else if after, ok := strings.CutPrefix(value, "ver:"); ok {
		value = strings.TrimSpace(after)
	}
	if index := strings.IndexByte(value, '-'); index >= 0 {
		value = value[:index]
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return hdcVersion{}, false
	}
	letter := byte(0)
	last := value[len(value)-1]
	if last >= 'A' && last <= 'Z' {
		last += 'a' - 'A'
	}
	if last >= 'a' && last <= 'z' {
		letter = last
		value = value[:len(value)-1]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return hdcVersion{}, false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	patch, errPatch := strconv.Atoi(parts[2])
	if errMajor != nil || errMinor != nil || errPatch != nil || major < 0 || minor < 0 || patch < 0 {
		return hdcVersion{}, false
	}
	return hdcVersion{major: major, minor: minor, patch: patch, letter: letter}, true
}

func compareHdcVersion(left, right hdcVersion) int {
	if left.major != right.major {
		return left.major - right.major
	}
	if left.minor != right.minor {
		return left.minor - right.minor
	}
	if left.patch != right.patch {
		return left.patch - right.patch
	}
	return int(left.letter) - int(right.letter)
}

// shellControlReplacer 复用同一个 Replacer 实例：strings.NewReplacer 每次调用都会重建匹配结构。
// 这里把分隔类控制字符统一折叠为空格，且折叠后的命令串既用于策略判定也用于下发设备，
// 两者一致，不存在「判定看到的」与「设备执行的」不同的问题。
var shellControlReplacer = strings.NewReplacer("\x00", " ", "\r", " ", "\n", " ")

// ExtractShellCommand 从 UnityExecute/UnityExecuteEx 帧提取一次性 shell 命令字符串，
// 规范化控制字符并拒绝非可打印 ASCII，作为进入策略检查前的安全清洗。
func ExtractShellCommand(frame Frame) string {
	var value []byte
	switch frame.CommandFlag {
	case CommandUnityExecute:
		value = frame.Payload
	case CommandUnityExecuteEx:
		value = extractTLVValue(frame.Payload, 0)
	default:
		return ""
	}
	text := strings.TrimSpace(shellControlReplacer.Replace(string(value)))
	if !utf8.ValidString(text) {
		return ""
	}
	for _, r := range text {
		if r < 32 || r > 126 {
			return ""
		}
	}
	return text
}

type payloadProtect struct {
	ChannelID   uint32
	CommandFlag Command
	CheckSum    uint8
	VCode       uint8
}

func decodeFrameHeader(header []byte) (uint16, uint32, error) {
	if len(header) != DaemonHeaderBytes || header[0] != 'H' || header[1] != 'W' {
		return 0, 0, fmt.Errorf("invalid HDC daemon frame header")
	}
	if header[2] != 0 || header[3] != 0 {
		return 0, 0, fmt.Errorf("unsupported HDC daemon frame options")
	}
	if header[4] != DaemonProtocolVersion {
		return 0, 0, fmt.Errorf("unsupported HDC daemon protocol version: %d", header[4])
	}
	protectSize := binary.BigEndian.Uint16(header[5:7])
	payloadSize := binary.BigEndian.Uint32(header[7:11])
	if protectSize == 0 {
		return 0, 0, fmt.Errorf("invalid HDC daemon frame size")
	}
	return protectSize, payloadSize, nil
}

func encodeProtect(channelID uint32, commandFlag Command, checksum uint8) []byte {
	var result []byte
	result = appendVarintField(result, 1, uint64(channelID))
	result = appendVarintField(result, 2, uint64(commandFlag))
	result = appendVarintField(result, 3, uint64(checksum))
	return appendVarintField(result, 4, DaemonVCode)
}

func decodeProtect(payload []byte) (payloadProtect, error) {
	cursor := newCursor(payload)
	var result payloadProtect
	var commandSeen bool
	for cursor.remaining() {
		key, err := cursor.varint()
		if err != nil {
			return payloadProtect{}, err
		}
		field, wire := int(key>>3), int(key&7)
		if wire != 0 {
			if err := cursor.skip(wire); err != nil {
				return payloadProtect{}, err
			}
			continue
		}
		value, err := cursor.varint()
		if err != nil {
			return payloadProtect{}, err
		}
		switch field {
		case 1:
			if value > uint64(^uint32(0)) {
				return payloadProtect{}, fmt.Errorf("HDC daemon channel ID is out of range: %d", value)
			}
			result.ChannelID = uint32(value)
		case 2:
			if value > uint64(^uint32(0)) {
				return payloadProtect{}, fmt.Errorf("HDC daemon command is out of range: %d", value)
			}
			result.CommandFlag = Command(value)
			commandSeen = true
		case 3:
			if value > uint64(^uint8(0)) {
				return payloadProtect{}, fmt.Errorf("HDC daemon checksum is out of range: %d", value)
			}
			result.CheckSum = uint8(value)
		case 4:
			if value > uint64(^uint8(0)) {
				return payloadProtect{}, fmt.Errorf("HDC daemon vcode is out of range: %d", value)
			}
			result.VCode = uint8(value)
		}
	}
	if !commandSeen {
		return payloadProtect{}, fmt.Errorf("HDC daemon command field is missing")
	}
	return result, nil
}

func payloadChecksum(payload []byte) uint8 {
	var checksum uint8
	for _, value := range payload {
		checksum += value
	}
	return checksum
}

func encodeSessionHandshake(handshake SessionHandshake) []byte {
	var result []byte
	result = appendStringField(result, 1, handshake.Banner)
	result = appendVarintField(result, 2, uint64(handshake.AuthType))
	result = appendVarintField(result, 3, uint64(handshake.SessionID))
	result = appendStringField(result, 4, handshake.ConnectKey)
	result = appendStringField(result, 5, handshake.Buffer)
	return appendStringField(result, 6, handshake.Version)
}

// authTLVFieldWidth 是认证成功 TLV 的定宽字段长度；tag 与长度都必须严格占满该宽度，
// 超长会把后续字段整体挪位，解析端只能读到错乱数据。
const authTLVFieldWidth = 16

func buildAuthSuccessTLV(deviceName string) string {
	return buildAuthStatusTLV(deviceName, "", DaemonAuthSuccess)
}

func buildAuthStatusTLV(deviceName, message, authStatus string) string {
	buffer := AppendHandshakeTLV("", "emgmsg", message)
	buffer = AppendHandshakeTLV(buffer, "devname", deviceName)
	buffer = AppendHandshakeTLV(buffer, "daemonauthstatus", authStatus)
	return AppendHandshakeTLV(buffer, "1200", "enable")
}

// AppendHandshakeTLV 按官方 16+16 定宽 TLV 追加一项。
func AppendHandshakeTLV(buffer, tag, value string) string {
	if len(tag) > authTLVFieldWidth {
		tag = tag[:authTLVFieldWidth]
	}
	return buffer + fmt.Sprintf("%-*s%-*d%s", authTLVFieldWidth, tag, authTLVFieldWidth, len(value), value)
}

// ParseHandshakeTLV 解析官方定宽握手 TLV。畸形输入返回错误，供能力协商 fail-open 到旧算法。
func ParseHandshakeTLV(buffer string) (map[string]string, error) {
	fields := make(map[string]string)
	remaining := buffer
	for remaining != "" {
		if len(remaining) < authTLVFieldWidth*2 {
			return nil, fmt.Errorf("HDC handshake TLV is truncated")
		}
		tag := strings.TrimSpace(remaining[:authTLVFieldWidth])
		lengthText := strings.TrimSpace(remaining[authTLVFieldWidth : authTLVFieldWidth*2])
		length := 0
		for _, r := range lengthText {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("HDC handshake TLV length is invalid")
			}
			length = length*10 + int(r-'0')
		}
		start := authTLVFieldWidth * 2
		if length < 0 || start+length > len(remaining) {
			return nil, fmt.Errorf("HDC handshake TLV value is truncated")
		}
		if tag != "" {
			fields[tag] = remaining[start : start+length]
		}
		remaining = remaining[start+length:]
	}
	return fields, nil
}

func extractTLVValue(payload []byte, expectedTag uint32) []byte {
	for offset := 0; offset+8 <= len(payload); {
		tag := binary.LittleEndian.Uint32(payload[offset : offset+4])
		length := int(binary.LittleEndian.Uint32(payload[offset+4 : offset+8]))
		start := offset + 8
		if length < 0 || start+length > len(payload) {
			return nil
		}
		if tag == expectedTag {
			return append([]byte(nil), payload[start:start+length]...)
		}
		offset = start + length
	}
	return nil
}

func appendVarintField(target []byte, field int, value uint64) []byte {
	target = binary.AppendUvarint(target, uint64(field<<3))
	return binary.AppendUvarint(target, value)
}

func appendStringField(target []byte, field int, value string) []byte {
	target = binary.AppendUvarint(target, uint64(field<<3|2))
	target = binary.AppendUvarint(target, uint64(len(value)))
	return append(target, value...)
}

type cursor struct {
	reader *bytes.Reader
}

func newCursor(data []byte) *cursor {
	return &cursor{reader: bytes.NewReader(data)}
}

func (c *cursor) remaining() bool {
	return c.reader.Len() > 0
}

func (c *cursor) varint() (uint64, error) {
	value, err := binary.ReadUvarint(c.reader)
	if err != nil {
		return 0, fmt.Errorf("read HDC protobuf varint: %w", err)
	}
	return value, nil
}

func (c *cursor) varintValue(wire int) (uint64, error) {
	if wire != 0 {
		return 0, fmt.Errorf("unexpected HDC protobuf varint wire type: %d", wire)
	}
	return c.varint()
}

func (c *cursor) stringValue(wire int) (string, error) {
	if wire != 2 {
		return "", fmt.Errorf("unexpected HDC protobuf string wire type: %d", wire)
	}
	length, err := c.varint()
	if err != nil {
		return "", err
	}
	if length > uint64(c.reader.Len()) {
		return "", fmt.Errorf("truncated HDC protobuf string")
	}
	value := make([]byte, int(length))
	if _, err := io.ReadFull(c.reader, value); err != nil {
		return "", err
	}
	return string(value), nil
}

func (c *cursor) skip(wire int) error {
	var size uint64
	switch wire {
	case 0:
		_, err := c.varint()
		return err
	case 1:
		size = 8
	case 2:
		length, err := c.varint()
		if err != nil {
			return err
		}
		size = length
	case 5:
		size = 4
	default:
		return fmt.Errorf("unsupported HDC protobuf wire type: %d", wire)
	}
	if size > uint64(c.reader.Len()) {
		return fmt.Errorf("truncated HDC protobuf field")
	}
	_, err := c.reader.Seek(int64(size), io.SeekCurrent)
	return err
}
