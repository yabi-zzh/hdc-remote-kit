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

func TestShellInputGuardCatchesCrossFrameCommand(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	// 高危命令 "reboot" 被拆到多帧发送，单帧各自合法，累积后必须被识别。
	if decision := policy.InspectShellCommand(connection.appendShellInput(5, []byte("reb"))); !decision.Allowed {
		t.Fatal("partial chunk 'reb' should not be rejected on its own")
	}
	guarded := connection.appendShellInput(5, []byte("oot\n"))
	if decision := policy.InspectShellCommand(guarded); decision.Allowed {
		t.Fatalf("accumulated %q should be rejected", guarded)
	}
	// channel 关闭时窗口随之清理（生产在 stopShell/removeShell 内联 delete）；此处直接重置验证隔离。
	delete(connection.shellInput, 5)
	if decision := policy.InspectShellCommand(connection.appendShellInput(5, []byte("ls\n"))); !decision.Allowed {
		t.Fatal("benign command after clear should be allowed")
	}
}

func TestShellInputGuardSlidingWindowBounded(t *testing.T) {
	connection := newTestDaemonConnection(protocol.NewCodec(4096))
	filler := make([]byte, shellInputGuardLimit)
	for index := range filler {
		filler[index] = 'a'
	}
	connection.appendShellInput(7, filler)
	guarded := connection.appendShellInput(7, []byte("b"))
	if len(guarded) != shellInputGuardLimit {
		t.Fatalf("guard window length = %d, want %d", len(guarded), shellInputGuardLimit)
	}
	if guarded[len(guarded)-1] != 'b' {
		t.Fatal("sliding window should retain the most recent byte")
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
