package bridge

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestAppBridgeInstallsSinglePackage(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "apps"), 1024)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	var output frameCapture
	commands := make(chan string, 1)
	bridge := NewAppBridge(context.Background(), codec, store, 1024, time.Second,
		func(_ context.Context, command string) (TargetChannel, error) {
			commands <- command
			return &appTestTarget{responses: [][]byte{[]byte("install ok")}}, nil
		}, output.write)

	config := protocol.TransferConfig{
		FileSize: 3, OptionalName: "sample.hap", FunctionName: "install", Options: "-r",
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandAppCheck, Payload: protocol.EncodeTransferConfig(config)}); err != nil {
		t.Fatalf("Handle(AppCheck) error = %v", err)
	}
	begin := output.waitFrame(t, codec, protocol.CommandAppBegin)
	if begin.ChannelID != 7 {
		t.Fatalf("begin channel = %d, want 7", begin.ChannelID)
	}

	data, err := protocol.EncodeTransferData(protocol.TransferPayload{
		Index: 0, Compression: protocol.CompressionNone, CompressedSize: 3, UncompressedSize: 3,
	}, []byte("abc"))
	if err != nil {
		t.Fatalf("EncodeTransferData() error = %v", err)
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandAppData, Payload: data}); err != nil {
		t.Fatalf("Handle(AppData) error = %v", err)
	}

	select {
	case command := <-commands:
		if !strings.HasPrefix(command, "install -r ") {
			t.Fatalf("target command = %q, want install -r prefix", command)
		}
		// 临时包必须带原始扩展名，否则设备侧 bm install 无法识别包类型。
		if !strings.HasSuffix(strings.TrimRight(command, `"`), "sample.hap") {
			t.Fatalf("target command = %q, want temp path ending with sample.hap", command)
		}
	case <-time.After(time.Second):
		t.Fatal("target install command was not opened")
	}
	finish := output.waitFrame(t, codec, protocol.CommandAppFinish)
	if len(finish.Payload) < 2 || finish.Payload[0] != appFinishModeInstall || finish.Payload[1] != appStatusSuccess {
		t.Fatalf("unexpected app finish payload = %q", finish.Payload)
	}
	if !bytes.Equal(finish.Payload[2:], []byte("install ok")) {
		t.Fatalf("finish message = %q", finish.Payload[2:])
	}
	if used := storeUsedBytes(store); used != 0 {
		t.Fatalf("temporary storage used bytes = %d, want 0", used)
	}
}

func TestAppBridgeRejectsInvalidTransferState(t *testing.T) {
	codec := protocol.NewCodec(4096)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "apps"), 1024)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	var output frameCapture
	opened := make(chan struct{}, 1)
	bridge := NewAppBridge(context.Background(), codec, store, 1024, time.Second,
		func(context.Context, string) (TargetChannel, error) {
			opened <- struct{}{}
			return &appTestTarget{responses: [][]byte{[]byte("unexpected")}}, nil
		}, output.write)

	invalid := protocol.TransferConfig{
		FileSize: 1, OptionalName: "sample.hap", FunctionName: "install", Compression: protocol.CompressionLZ4,
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 1, CommandFlag: protocol.CommandAppCheck, Payload: protocol.EncodeTransferConfig(invalid)}); err != nil {
		t.Fatalf("Handle(invalid AppCheck) error = %v", err)
	}
	finish := output.waitFrame(t, codec, protocol.CommandAppFinish)
	if len(finish.Payload) < 2 || finish.Payload[1] != appStatusFail || !bytes.Contains(finish.Payload[2:], []byte("Compressed")) {
		t.Fatalf("unexpected invalid config result = %q", finish.Payload)
	}

	valid := protocol.TransferConfig{FileSize: 2, OptionalName: "sample.hap", FunctionName: "install"}
	if err := bridge.Handle(protocol.Frame{ChannelID: 2, CommandFlag: protocol.CommandAppCheck, Payload: protocol.EncodeTransferConfig(valid)}); err != nil {
		t.Fatalf("Handle(valid AppCheck) error = %v", err)
	}
	output.waitFrame(t, codec, protocol.CommandAppBegin)
	data, err := protocol.EncodeTransferData(protocol.TransferPayload{
		Index: 1, Compression: protocol.CompressionNone, CompressedSize: 1, UncompressedSize: 1,
	}, []byte("a"))
	if err != nil {
		t.Fatalf("EncodeTransferData() error = %v", err)
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 2, CommandFlag: protocol.CommandAppData, Payload: data}); err != nil {
		t.Fatalf("Handle(out-of-order AppData) error = %v", err)
	}
	finish = output.waitFrame(t, codec, protocol.CommandAppFinish)
	if len(finish.Payload) < 2 || finish.Payload[1] != appStatusFail {
		t.Fatalf("unexpected out-of-order result = %q", finish.Payload)
	}
	select {
	case <-opened:
		t.Fatal("invalid transfer opened target command")
	default:
	}
	if used := storeUsedBytes(store); used != 0 {
		t.Fatalf("temporary storage used bytes after rejection = %d", used)
	}
}

func TestAppBridgeUninstallAndCloseReleaseTarget(t *testing.T) {
	codec := protocol.NewCodec(4096)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "apps"), 1024)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	var output frameCapture
	target := &appTestTarget{responses: [][]byte{[]byte("uninstall ok")}}
	commands := make(chan string, 1)
	bridge := NewAppBridge(context.Background(), codec, store, 1024, time.Second,
		func(_ context.Context, command string) (TargetChannel, error) {
			commands <- command
			return target, nil
		}, output.write)
	// 真机负载：hdc 客户端下发完整 "uninstall <opts> <bundle>"。
	if err := bridge.Handle(protocol.Frame{ChannelID: 3, CommandFlag: protocol.CommandAppUninstall, Payload: []byte("uninstall -s com.example.demo")}); err != nil {
		t.Fatalf("Handle(AppUninstall) error = %v", err)
	}
	select {
	case command := <-commands:
		if command != "uninstall -s com.example.demo" {
			t.Fatalf("uninstall command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("target uninstall command was not opened")
	}
	finish := output.waitFrame(t, codec, protocol.CommandAppFinish)
	if len(finish.Payload) < 2 || finish.Payload[0] != appFinishModeUninstall || finish.Payload[1] != appStatusSuccess {
		t.Fatalf("unexpected uninstall result = %q", finish.Payload)
	}

	blocking := &appTestTarget{block: make(chan struct{})}
	bridge = NewAppBridge(context.Background(), codec, store, 1024, time.Second,
		func(context.Context, string) (TargetChannel, error) { return blocking, nil }, output.write)
	// 真机 payload 为纯 bundle name 且以 NUL 结尾。
	if err := bridge.Handle(protocol.Frame{ChannelID: 4, CommandFlag: protocol.CommandAppUninstall, Payload: []byte("com.example.blocked\x00")}); err != nil {
		t.Fatalf("Handle(blocking AppUninstall) error = %v", err)
	}
	waitForTarget(t, blocking)
	bridge.CloseChannel(4)
	select {
	case <-blocking.closed:
	case <-time.After(time.Second):
		t.Fatal("closing app channel did not close target")
	}
}

type frameCapture struct {
	mu     sync.Mutex
	frames [][]byte
}

func (c *frameCapture) write(frame []byte) error {
	c.mu.Lock()
	c.frames = append(c.frames, append([]byte(nil), frame...))
	c.mu.Unlock()
	return nil
}

func (c *frameCapture) waitFrame(t *testing.T, codec *protocol.Codec, command protocol.Command) protocol.Frame {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		frames := append([][]byte(nil), c.frames...)
		c.mu.Unlock()
		for _, raw := range frames {
			frame, err := codec.Decode(raw)
			if err != nil {
				t.Fatalf("Decode(captured frame) error = %v", err)
			}
			if frame.CommandFlag == command {
				return frame
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for command %d", command)
	return protocol.Frame{}
}

type appTestTarget struct {
	mu        sync.Mutex
	responses [][]byte
	block     chan struct{}
	closed    chan struct{}
	once      sync.Once
}

func (t *appTestTarget) ReadPayload() ([]byte, error) {
	if t.closed == nil {
		t.mu.Lock()
		t.closed = make(chan struct{})
		t.mu.Unlock()
	}
	if t.block != nil {
		<-t.block
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.responses) == 0 {
		return nil, io.EOF
	}
	response := t.responses[0]
	t.responses = t.responses[1:]
	return response, io.EOF
}

func (t *appTestTarget) WritePayload([]byte) error { return nil }

func (t *appTestTarget) Close() error {
	if t.closed == nil {
		t.mu.Lock()
		if t.closed == nil {
			t.closed = make(chan struct{})
		}
		t.mu.Unlock()
	}
	t.once.Do(func() { close(t.closed) })
	if t.block != nil {
		select {
		case <-t.block:
		default:
			close(t.block)
		}
	}
	return nil
}

func waitForTarget(t *testing.T, target *appTestTarget) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		target.mu.Lock()
		started := target.closed != nil
		target.mu.Unlock()
		if started {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("target was not started")
}

func storeUsedBytes(store *TempStore) int64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.usedBytes
}
