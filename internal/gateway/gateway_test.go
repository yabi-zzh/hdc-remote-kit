package gateway

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/bridge"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/policy"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestDaemonConnectionRequiresHandshake(t *testing.T) {
	codec := protocol.NewCodec(2048)
	frame, err := codec.Decode(codec.EncodeFrame(1, protocol.CommandShellInit, nil))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	connection := newTestDaemonConnection(codec)
	if err := connection.route(frame); err == nil {
		t.Fatal("route() error = nil, want handshake violation")
	} else if _, ok := err.(*daemonProtocolViolation); !ok {
		t.Fatalf("route() error type = %T, want *daemonProtocolViolation", err)
	}
}

func TestDaemonConnectionHandshakeWritesAcceptedAndCloseFrames(t *testing.T) {
	codec := protocol.NewCodec(4096)
	connection := newTestDaemonConnection(codec)
	request, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, SessionID: 27,
		ConnectKey: "127.0.0.1:1234", Version: "Ver: 3.2.0c-test",
	}))
	if err != nil {
		t.Fatalf("Decode(handshake) error = %v", err)
	}
	if err := connection.route(request); err != nil {
		t.Fatalf("route(handshake) error = %v", err)
	}
	if !connection.handshakeAccepted {
		t.Fatal("handshakeAccepted = false")
	}

	reader := bytes.NewReader(connection.conn.(*memoryConn).Bytes())
	acceptedRaw, err := codec.ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame(accepted) error = %v", err)
	}
	accepted, err := codec.Decode(acceptedRaw)
	if err != nil {
		t.Fatalf("Decode(accepted) error = %v", err)
	}
	if accepted.CommandFlag != protocol.CommandKernelHandshake {
		t.Fatalf("accepted command = %d", accepted.CommandFlag)
	}
	closeRaw, err := codec.ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame(close) error = %v", err)
	}
	closeFrame, err := codec.Decode(closeRaw)
	if err != nil {
		t.Fatalf("Decode(close) error = %v", err)
	}
	if closeFrame.CommandFlag != protocol.CommandKernelChannelClose || !bytes.Equal(closeFrame.Payload, []byte{1}) {
		t.Fatalf("unexpected handshake close frame = %+v", closeFrame)
	}
	if reader.Len() != 0 {
		t.Fatalf("handshake response has %d trailing bytes", reader.Len())
	}
	if err := connection.route(request); err == nil {
		t.Fatal("repeated handshake error = nil")
	}
}

func newTestDaemonConnection(codec *protocol.Codec) *daemonConnection {
	return &daemonConnection{
		conn:       &memoryConn{},
		binding:    model.Binding{DeviceID: "device-1"},
		codec:      codec,
		shells:     make(map[uint32]*shellSession),
		shellInput: make(map[uint32]*strings.Builder),
	}
}

func mustAppendShellInput(t *testing.T, connection *daemonConnection, channelID uint32, chunk string) string {
	t.Helper()
	guarded, ok := connection.appendShellInput(channelID, []byte(chunk))
	if !ok {
		t.Fatalf("appendShellInput(%q) rejected the input", chunk)
	}
	return guarded
}

func TestShellInputGuardCatchesCrossFrameCommand(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	// 高危命令 "reboot" 被拆到多帧发送，单帧各自合法，累积后必须被识别。
	if decision := policy.InspectShellCommand(mustAppendShellInput(t, connection, 5, "reb")); !decision.Allowed {
		t.Fatal("partial chunk 'reb' should not be rejected on its own")
	}
	guarded := mustAppendShellInput(t, connection, 5, "oot\n")
	if decision := policy.InspectShellCommand(guarded); decision.Allowed {
		t.Fatalf("accumulated %q should be rejected", guarded)
	}
	// channel 关闭时窗口随之清理（生产在 stopShell/removeShell 内联 delete）；此处直接重置验证隔离。
	delete(connection.shellInput, 5)
	if decision := policy.InspectShellCommand(mustAppendShellInput(t, connection, 5, "ls\n")); !decision.Allowed {
		t.Fatal("benign command after clear should be allowed")
	}
}

// TestShellInputGuardDropsCompletedLines 确认已成行的输入不再留在窗口里：
// 否则每次按键都要重新解析整个历史，判定成本随会话长度二次增长。
func TestShellInputGuardDropsCompletedLines(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	mustAppendShellInput(t, connection, 7, "echo hello\n")
	guarded := mustAppendShellInput(t, connection, 7, "ls")
	if guarded != "ls" {
		t.Fatalf("guard window = %q, want only the pending line %q", guarded, "ls")
	}
}

// TestShellInputGuardInspectsEntireChunk 确认护栏检查本帧送达设备的全部输入。
// 若只截取窗口尾部，「大段填充 + 高危命令」会把命令挤出检查范围而被放行。
func TestShellInputGuardInspectsEntireChunk(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	padding := strings.Repeat("a", shellInputGuardLimit)
	guarded := mustAppendShellInput(t, connection, 7, "reboot\n"+padding)
	if decision := policy.InspectShellCommand(guarded); decision.Allowed {
		t.Fatal("high-risk command followed by padding should still be rejected")
	}
}

// TestShellInputGuardRejectsOversizedInput 超过判定上限时必须拒绝该帧，
// 而不是缩小检查范围后把未检查的内容转发给设备。
func TestShellInputGuardRejectsOversizedInput(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	oversized := make([]byte, shellInputInspectLimit+1)
	for index := range oversized {
		oversized[index] = 'a'
	}
	if _, ok := connection.appendShellInput(7, oversized); ok {
		t.Fatal("oversized shell input should be rejected")
	}
}

// TestShellInputGuardBoundsPendingLine 一直没有换行的超长输入只保留尾部，避免残行无界增长。
func TestShellInputGuardBoundsPendingLine(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	filler := strings.Repeat("a", shellInputGuardLimit)
	mustAppendShellInput(t, connection, 7, filler)
	guarded := mustAppendShellInput(t, connection, 7, "b")
	if guarded[len(guarded)-1] != 'b' {
		t.Fatal("guard window should retain the most recent byte")
	}
	if retained := connection.shellInput[7].Len(); retained != shellInputGuardLimit {
		t.Fatalf("pending line length = %d, want %d", retained, shellInputGuardLimit)
	}
}

type memoryConn struct {
	bytes.Buffer
}

func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return testAddress("local") }
func (c *memoryConn) RemoteAddr() net.Addr             { return testAddress("remote") }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddress string

func (a testAddress) Network() string { return "memory" }
func (a testAddress) String() string  { return string(a) }

type gatewayUnityTarget struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (t *gatewayUnityTarget) ReadPayload() ([]byte, error) {
	<-t.closed
	return nil, net.ErrClosed
}

func (t *gatewayUnityTarget) WritePayload([]byte) error { return nil }

func (t *gatewayUnityTarget) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func TestDaemonConnectionRoutesUnityFamily(t *testing.T) {
	codec := protocol.NewCodec(4096)
	connection := newTestDaemonConnection(codec)
	connection.handshakeAccepted = true
	opened := make(chan string, 1)
	target := &gatewayUnityTarget{closed: make(chan struct{})}
	connection.unityBridge = bridge.NewUnityBridge(context.Background(), codec, time.Second,
		func(_ context.Context, command string) (bridge.TargetChannel, error) {
			opened <- command
			return target, nil
		}, connection.write)
	defer connection.unityBridge.Close()

	frame, err := codec.Decode(codec.EncodeFrame(3, protocol.CommandUnityHilog, []byte("h")))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := connection.route(frame); err != nil {
		t.Fatalf("route(UnityHilog) error = %v", err)
	}
	select {
	case command := <-opened:
		if command != "hilog -h" {
			t.Fatalf("target command = %q, want %q", command, "hilog -h")
		}
	case <-time.After(time.Second):
		t.Fatal("Unity bridge did not open target channel")
	}
}
