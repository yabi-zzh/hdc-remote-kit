package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestForwardBridgeTCPContextsAndCleanup(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	var output forwardFrameCapture
	accepted := make(chan net.Conn, 2)
	cleanupCommands := make(chan string, 1)
	listeners := make(map[int]net.Listener)
	var listenersMu sync.Mutex

	openTarget := func(_ context.Context, command string) (TargetChannel, error) {
		fields := strings.Fields(command)
		if len(fields) >= 3 && fields[0] == "fport" && strings.HasPrefix(fields[1], "tcp:") {
			localPort, err := strconv.Atoi(strings.TrimPrefix(fields[1], "tcp:"))
			if err != nil {
				return nil, err
			}
			listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
			if err != nil {
				return nil, err
			}
			listenersMu.Lock()
			listeners[localPort] = listener
			listenersMu.Unlock()
			go func() {
				for {
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					accepted <- conn
				}
			}()
			return &forwardTestTarget{payloads: [][]byte{[]byte("Forwardport result:OK")}}, nil
		}
		if len(fields) == 4 && fields[0] == "fport" && fields[1] == "rm" {
			cleanupCommands <- command
			port, err := strconv.Atoi(strings.TrimPrefix(fields[2], "tcp:"))
			if err != nil {
				return nil, err
			}
			listenersMu.Lock()
			listener := listeners[port]
			delete(listeners, port)
			listenersMu.Unlock()
			if listener != nil {
				_ = listener.Close()
			}
			return &forwardTestTarget{}, nil
		}
		return nil, io.ErrUnexpectedEOF
	}

	bridge := NewForwardBridge(context.Background(), codec, time.Second, openTarget, output.write)
	checkContextID := uint32(11)
	if err := bridge.Handle(protocol.Frame{
		ChannelID:   7,
		CommandFlag: protocol.CommandForwardCheck,
		Payload:     forwardEndpointPayload(checkContextID, "tcp:8081"),
	}); err != nil {
		t.Fatalf("Handle(ForwardCheck) error = %v", err)
	}
	checkResult := output.wait(t, codec, protocol.CommandForwardCheckResult)
	if !bytes.Equal(checkResult.Payload, appendForwardContext(checkContextID, []byte{0})) {
		t.Fatalf("check result payload = %v, want context %d and success flag", checkResult.Payload, checkContextID)
	}

	binding := bridge.bindings[7]
	if binding == nil {
		t.Fatal("ForwardCheck did not create channel binding")
	}
	firstContextID := uint32(21)
	if err := bridge.Handle(protocol.Frame{
		ChannelID:   7,
		CommandFlag: protocol.CommandForwardActiveSlave,
		Payload:     forwardEndpointPayload(firstContextID, "tcp:8081"),
	}); err != nil {
		t.Fatalf("Handle(first ForwardActiveSlave) error = %v", err)
	}
	activeMaster := output.wait(t, codec, protocol.CommandForwardActiveMaster)
	if !bytes.Equal(activeMaster.Payload, appendForwardContext(firstContextID, nil)) {
		t.Fatalf("active master payload = %v, want context %d", activeMaster.Payload, firstContextID)
	}
	firstConn := waitForwardAccepted(t, accepted)
	defer firstConn.Close()

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   7,
		CommandFlag: protocol.CommandForwardData,
		Payload:     appendForwardContext(firstContextID, []byte("from-remote")),
	}); err != nil {
		t.Fatalf("Handle(first ForwardData) error = %v", err)
	}
	assertForwardRead(t, firstConn, []byte("from-remote"))

	if _, err := firstConn.Write([]byte("to-remote")); err != nil {
		t.Fatalf("write first local TCP context = %v", err)
	}
	firstData := output.waitPayload(t, codec, protocol.CommandForwardData, appendForwardContext(firstContextID, []byte("to-remote")))
	if !bytes.Equal(firstData.Payload, appendForwardContext(firstContextID, []byte("to-remote"))) {
		t.Fatalf("first forwarded data payload = %v", firstData.Payload)
	}

	secondContextID := uint32(22)
	if err := bridge.Handle(protocol.Frame{
		ChannelID:   7,
		CommandFlag: protocol.CommandForwardActiveSlave,
		Payload:     forwardEndpointPayload(secondContextID, "tcp:8081"),
	}); err != nil {
		t.Fatalf("Handle(second ForwardActiveSlave) error = %v", err)
	}
	output.wait(t, codec, protocol.CommandForwardActiveMaster)
	secondConn := waitForwardAccepted(t, accepted)
	defer secondConn.Close()

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   7,
		CommandFlag: protocol.CommandForwardFreeContext,
		Payload:     appendForwardContext(firstContextID, nil),
	}); err != nil {
		t.Fatalf("Handle(first ForwardFreeContext) error = %v", err)
	}
	if err := secondConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(second context) error = %v", err)
	}
	if _, err := secondConn.Write([]byte("second-still-open")); err != nil {
		t.Fatalf("second context write after first release = %v", err)
	}
	secondData := output.waitPayload(t, codec, protocol.CommandForwardData, appendForwardContext(secondContextID, []byte("second-still-open")))
	if !bytes.Equal(secondData.Payload, appendForwardContext(secondContextID, []byte("second-still-open"))) {
		t.Fatalf("second forwarded data payload = %v", secondData.Payload)
	}

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   7,
		CommandFlag: protocol.CommandForwardFreeContext,
		Payload:     appendForwardContext(checkContextID, nil),
	}); err != nil {
		t.Fatalf("Handle(check ForwardFreeContext) error = %v", err)
	}
	select {
	case command := <-cleanupCommands:
		// 清理必须用完整 ruler：本地端点 + 设备端点，否则主 HDC 删除失败泄漏转发。
		if !strings.HasPrefix(command, "fport rm tcp:") || !strings.HasSuffix(command, " tcp:8081") {
			t.Fatalf("cleanup command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("forward cleanup command was not opened")
	}

	bridge.Close()
}

func TestForwardBridgeRejectsUnsupportedEndpoint(t *testing.T) {
	codec := protocol.NewCodec(4096)
	var output forwardFrameCapture
	bridge := NewForwardBridge(context.Background(), codec, time.Second,
		func(context.Context, string) (TargetChannel, error) {
			t.Fatal("unsupported endpoint opened target channel")
			return nil, nil
		}, output.write)

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   3,
		CommandFlag: protocol.CommandForwardCheck,
		Payload:     forwardEndpointPayload(1, "jdwp:5005"),
	}); err != nil {
		t.Fatalf("Handle(unsupported ForwardCheck) error = %v", err)
	}
	frame := output.wait(t, codec, protocol.CommandKernelEchoRaw)
	if !bytes.Contains(frame.Payload, []byte("not supported")) {
		t.Fatalf("unsupported endpoint response = %q", frame.Payload)
	}
}

func TestValidateForwardEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		allowed  bool
	}{
		{"tcp:8080", true},
		{"tcp:0", false},
		{"tcp:70000", false},
		{"tcp:abc", false},
		{"localabstract:chrome_devtools_remote", true},
		{"localreserved:com.example.app.sock", true},
		{"localfilesystem:/data/local/tmp/app.sock", true},
		{"localabstract:", false},
		{"localabstract:-inject", false},
		{"localabstract:a b", false},
		{"localabstract:a;rm", false},
		{"localabstract:a$(x)", false},
		{"jdwp:5005", false},
		{"ark:1234", false},
		{"dev:ttyS0", false},
		{"", false},
		{"tcp:80\r", false},
	}
	for _, testCase := range cases {
		err := validateForwardEndpoint(testCase.endpoint)
		if testCase.allowed && err != nil {
			t.Errorf("validateForwardEndpoint(%q) = %v, want allowed", testCase.endpoint, err)
		}
		if !testCase.allowed && err == nil {
			t.Errorf("validateForwardEndpoint(%q) = nil, want rejected", testCase.endpoint)
		}
	}
}

func TestForwardBridgeReversePortFlow(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	var output forwardFrameCapture
	rportCommands := make(chan string, 1)
	openTarget := func(_ context.Context, command string) (TargetChannel, error) {
		fields := strings.Fields(command)
		if len(fields) == 3 && fields[0] == "rport" {
			rportCommands <- command
			return &forwardTestTarget{payloads: [][]byte{[]byte("Forwardport result:OK")}}, nil
		}
		return &forwardTestTarget{}, nil
	}
	bridge := NewForwardBridge(context.Background(), codec, time.Second, openTarget, output.write)
	defer bridge.Close()

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   8,
		CommandFlag: protocol.CommandForwardInit,
		Payload:     []byte("tcp:8888 tcp:9999"),
	}); err != nil {
		t.Fatalf("Handle(ForwardInit rport) error = %v", err)
	}

	var gatewayPort int
	select {
	case command := <-rportCommands:
		fields := strings.Fields(command)
		port, err := strconv.Atoi(strings.TrimPrefix(fields[2], "tcp:"))
		if err != nil {
			t.Fatalf("parse gateway port from %q error = %v", command, err)
		}
		gatewayPort = port
	case <-time.After(time.Second):
		t.Fatal("rport setup command was not opened")
	}

	check := output.wait(t, codec, protocol.CommandForwardCheck)
	checkContextID := binary.BigEndian.Uint32(check.Payload[:forwardContextBytes])
	if endpoint := forwardEndpointFromPayload(check.Payload); endpoint != "tcp:9999" {
		t.Fatalf("check endpoint = %q, want tcp:9999", endpoint)
	}

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   8,
		CommandFlag: protocol.CommandForwardCheckResult,
		Payload:     appendForwardContext(checkContextID, []byte{0}),
	}); err != nil {
		t.Fatalf("Handle(ForwardCheckResult) error = %v", err)
	}
	output.wait(t, codec, protocol.CommandForwardSuccess)

	// 模拟设备侧反向连接：主 HDC 连回 gateway 监听端口
	deviceConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(gatewayPort)))
	if err != nil {
		t.Fatalf("dial gateway reverse port error = %v", err)
	}
	defer deviceConn.Close()

	activeSlave := output.wait(t, codec, protocol.CommandForwardActiveSlave)
	connContextID := binary.BigEndian.Uint32(activeSlave.Payload[:forwardContextBytes])

	if err := bridge.Handle(protocol.Frame{
		ChannelID:   8,
		CommandFlag: protocol.CommandForwardActiveMaster,
		Payload:     appendForwardContext(connContextID, nil),
	}); err != nil {
		t.Fatalf("Handle(ForwardActiveMaster) error = %v", err)
	}

	// 设备 → 主机方向：deviceConn 写入 → gateway 转 CMD_FORWARD_DATA 给用户 server
	if _, err := deviceConn.Write([]byte("device-out")); err != nil {
		t.Fatalf("device conn write error = %v", err)
	}
	output.waitPayload(t, codec, protocol.CommandForwardData, appendForwardContext(connContextID, []byte("device-out")))

	// 主机 → 设备方向：用户 server 发 CMD_FORWARD_DATA → gateway 写入 deviceConn
	if err := bridge.Handle(protocol.Frame{
		ChannelID:   8,
		CommandFlag: protocol.CommandForwardData,
		Payload:     appendForwardContext(connContextID, []byte("host-in")),
	}); err != nil {
		t.Fatalf("Handle(ForwardData host->device) error = %v", err)
	}
	assertForwardRead(t, deviceConn, []byte("host-in"))
}

func forwardEndpointFromPayload(payload []byte) string {
	prefix := forwardContextBytes + forwardPaddingBytes
	if len(payload) <= prefix {
		return ""
	}
	data := payload[prefix:]
	if index := bytes.IndexByte(data, 0); index >= 0 {
		data = data[:index]
	}
	return string(data)
}

type forwardFrameCapture struct {
	mu     sync.Mutex
	frames [][]byte
}

func (c *forwardFrameCapture) write(frame []byte) error {
	c.mu.Lock()
	c.frames = append(c.frames, append([]byte(nil), frame...))
	c.mu.Unlock()
	return nil
}

func (c *forwardFrameCapture) wait(t *testing.T, codec *protocol.Codec, command protocol.Command) protocol.Frame {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		frames := append([][]byte(nil), c.frames...)
		c.mu.Unlock()
		for _, raw := range frames {
			for _, frame := range decodeForwardCapture(t, codec, raw) {
				if frame.CommandFlag == command {
					return frame
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for command %d", command)
	return protocol.Frame{}
}

func (c *forwardFrameCapture) waitPayload(t *testing.T, codec *protocol.Codec, command protocol.Command, payload []byte) protocol.Frame {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		frames := append([][]byte(nil), c.frames...)
		c.mu.Unlock()
		for _, raw := range frames {
			for _, frame := range decodeForwardCapture(t, codec, raw) {
				if frame.CommandFlag == command && bytes.Equal(frame.Payload, payload) {
					return frame
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for command %d payload %q", command, payload)
	return protocol.Frame{}
}

func decodeForwardCapture(t *testing.T, codec *protocol.Codec, raw []byte) []protocol.Frame {
	t.Helper()
	reader := bytes.NewReader(raw)
	frames := make([]protocol.Frame, 0, 2)
	for reader.Len() > 0 {
		rawFrame, err := codec.ReadFrame(reader)
		if err != nil {
			t.Fatalf("ReadFrame(captured stream) error = %v", err)
		}
		frame, err := codec.Decode(rawFrame)
		if err != nil {
			t.Fatalf("Decode(captured frame) error = %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

type forwardTestTarget struct {
	mu       sync.Mutex
	payloads [][]byte
	closed   bool
}

func (t *forwardTestTarget) ReadPayload() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.payloads) == 0 {
		return nil, io.EOF
	}
	payload := append([]byte(nil), t.payloads[0]...)
	t.payloads = t.payloads[1:]
	return payload, nil
}

func (t *forwardTestTarget) WritePayload([]byte) error { return nil }

func (t *forwardTestTarget) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	return nil
}

func forwardEndpointPayload(contextID uint32, endpoint string) []byte {
	data := append(make([]byte, forwardPaddingBytes), []byte(endpoint+"\x00")...)
	return appendForwardContext(contextID, data)
}

func appendForwardContext(contextID uint32, data []byte) []byte {
	payload := make([]byte, forwardContextBytes+len(data))
	binary.BigEndian.PutUint32(payload[:forwardContextBytes], contextID)
	copy(payload[forwardContextBytes:], data)
	return payload
}

func waitForwardAccepted(t *testing.T, accepted <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case conn := <-accepted:
		return conn
	case <-time.After(time.Second):
		t.Fatal("forward listener did not accept TCP context")
		return nil
	}
}

func assertForwardRead(t *testing.T, conn net.Conn, expected []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, actual); err != nil {
		t.Fatalf("read forwarded data error = %v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("forwarded data = %q, want %q", actual, expected)
	}
}
