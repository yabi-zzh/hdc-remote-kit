package bridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestFileBridgeUploadsSingleUncompressedFile(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	tempRoot := filepath.Join(t.TempDir(), "transfers")
	store, err := NewTempStore(tempRoot, 1024)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	writer := &syncBuffer{}
	target := &fakeTargetChannel{responses: [][]byte{{}, []byte("upload ok")}}
	commands := make(chan string, 4)
	bridge := NewFileBridge(context.Background(), codec, store, 1024, time.Second,
		func(_ context.Context, command string) (TargetChannel, error) {
			commands <- command
			return target, nil
		}, writer.write)
	defer bridge.Close()

	config := protocol.TransferConfig{FileSize: 3, Path: "/data/local/tmp/payload.txt", OptionalName: "payload.txt"}
	writer.reset()
	checkFrame := protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandFileCheck, Payload: protocol.EncodeTransferConfig(config)}
	if err := bridge.Handle(checkFrame); err != nil {
		t.Fatalf("Handle(FileCheck) error = %v", err)
	}
	begin := decodeWrittenFrame(t, codec, writer.snapshot())
	if begin.CommandFlag != protocol.CommandFileBegin {
		t.Fatalf("begin command = %d", begin.CommandFlag)
	}

	writer.reset()
	data, err := protocol.EncodeTransferData(protocol.TransferPayload{
		Index: 0, Compression: protocol.CompressionNone, CompressedSize: 3, UncompressedSize: 3,
	}, []byte("abc"))
	if err != nil {
		t.Fatalf("EncodeTransferData() error = %v", err)
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandFileData, Payload: data}); err != nil {
		t.Fatalf("Handle(FileData) error = %v", err)
	}
	finishRequest := decodeWrittenFrame(t, codec, writer.snapshot())
	if finishRequest.CommandFlag != protocol.CommandFileFinish || !bytes.Equal(finishRequest.Payload, []byte{fileFinishCurrentFile}) {
		t.Fatalf("unexpected current-file finish = %+v", finishRequest)
	}

	writer.reset()
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandFileFinish, Payload: []byte{fileFinishAll}}); err != nil {
		t.Fatalf("Handle(FileFinish) error = %v", err)
	}
	writer.waitNonEmpty(t)
	var command string
	select {
	case command = <-commands:
	case <-time.After(time.Second):
		t.Fatal("target channel was never opened")
	}
	if !strings.HasPrefix(command, "file send ") {
		t.Fatalf("target command = %q, want a file send command", command)
	}
	// 客户端声明的 OptionalName 必须体现在下发给设备的源文件名上，
	// 否则目标路径是目录时设备侧会落盘为临时文件名 "payload"。
	if !strings.Contains(command, "payload.txt") {
		t.Fatalf("target command = %q, want it to carry the declared file name", command)
	}
	if !strings.HasSuffix(strings.Trim(command[strings.LastIndex(command, " ")+1:], `"`), "/data/local/tmp/payload.txt") {
		t.Fatalf("target command = %q, want it to end with the requested target path", command)
	}
	if _, err := os.Stat(tempRoot); err != nil {
		t.Fatalf("transfer root disappeared unexpectedly: %v", err)
	}
}

// TestFileBridgeUploadTimeoutClosesTargetChannel 固化上传路径的超时看门狗。
// TargetChannel 的读取是阻塞式的，超时必须真的去关闭 channel，
// 只建一个带 deadline 的 context 并不会让阻塞中的读返回，超时会形同虚设。
func TestFileBridgeUploadTimeoutClosesTargetChannel(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "transfers"), 1024)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	writer := &syncBuffer{}
	target := newBlockingTargetChannel()
	bridge := NewFileBridge(context.Background(), codec, store, 1024, 50*time.Millisecond,
		func(context.Context, string) (TargetChannel, error) { return target, nil }, writer.write)
	defer bridge.Close()

	config := protocol.TransferConfig{FileSize: 3, Path: "/data/local/tmp/a.txt", OptionalName: "a.txt"}
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandFileCheck, Payload: protocol.EncodeTransferConfig(config)}); err != nil {
		t.Fatalf("Handle(FileCheck) error = %v", err)
	}
	data, err := protocol.EncodeTransferData(protocol.TransferPayload{
		Index: 0, Compression: protocol.CompressionNone, CompressedSize: 3, UncompressedSize: 3,
	}, []byte("abc"))
	if err != nil {
		t.Fatalf("EncodeTransferData() error = %v", err)
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandFileData, Payload: data}); err != nil {
		t.Fatalf("Handle(FileData) error = %v", err)
	}
	if err := bridge.Handle(protocol.Frame{ChannelID: 7, CommandFlag: protocol.CommandFileFinish, Payload: []byte{fileFinishAll}}); err != nil {
		t.Fatalf("Handle(FileFinish) error = %v", err)
	}
	select {
	case <-target.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("upload timeout did not close the target channel")
	}
}

// TestFileBridgeDownloadTimeoutClosesTargetChannel 固化 recv 路径的超时看门狗。
func TestFileBridgeDownloadTimeoutClosesTargetChannel(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "transfers"), 1<<20)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	writer := &syncBuffer{}
	target := newBlockingTargetChannel()
	bridge := NewFileBridge(context.Background(), codec, store, 1<<20, 50*time.Millisecond,
		func(context.Context, string) (TargetChannel, error) { return target, nil }, writer.write)
	defer bridge.Close()

	initFrame := protocol.Frame{ChannelID: 9, CommandFlag: protocol.CommandFileInit, Payload: []byte(`/data/local/tmp/a.txt ./a.txt`)}
	if err := bridge.Handle(initFrame); err != nil {
		t.Fatalf("Handle(FileInit) error = %v", err)
	}
	select {
	case <-target.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("download timeout did not close the target channel")
	}
}

// blockingTargetChannel 模拟一条永不返回数据的 target channel：
// ReadPayload 一直阻塞到 Close 被调用，用于验证超时确实会去关闭 channel。
type blockingTargetChannel struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newBlockingTargetChannel() *blockingTargetChannel {
	return &blockingTargetChannel{closed: make(chan struct{})}
}

func (t *blockingTargetChannel) ReadPayload() ([]byte, error) {
	<-t.closed
	return nil, net.ErrClosed
}

func (t *blockingTargetChannel) WritePayload([]byte) error { return nil }

func (t *blockingTargetChannel) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func TestFileBridgeRejectsUnsupportedTransferModes(t *testing.T) {
	codec := protocol.NewCodec(4096)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "transfers"), 1024)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	var written bytes.Buffer
	bridge := NewFileBridge(context.Background(), codec, store, 1024, time.Second, nil, func(frame []byte) error {
		_, err := written.Write(frame)
		return err
	})
	for _, config := range []protocol.TransferConfig{
		{FileSize: 1, Path: "/tmp/a", Compression: protocol.CompressionLZ4},
		{FileSize: 1, Path: "/tmp/a", UpdateIfNew: true},
		{FileSize: 1, Path: "/tmp/a", OptionalName: "nested/name"},
	} {
		written.Reset()
		if err := bridge.Handle(protocol.Frame{ChannelID: 1, CommandFlag: protocol.CommandFileCheck, Payload: protocol.EncodeTransferConfig(config)}); err != nil {
			t.Fatalf("Handle() error = %v", err)
		}
		frame := decodeWrittenFrame(t, codec, written.Bytes())
		if frame.CommandFlag != protocol.CommandKernelEchoRaw {
			t.Fatalf("rejection command = %d", frame.CommandFlag)
		}
	}
	// 空/畸形的 recv 发起帧应被拒绝（recv 已实现，但输入非法）。
	written.Reset()
	if err := bridge.Handle(protocol.Frame{ChannelID: 2, CommandFlag: protocol.CommandFileInit}); err != nil {
		t.Fatalf("Handle(FileInit) error = %v", err)
	}
	frame := decodeWrittenFrame(t, codec, written.Bytes())
	if frame.CommandFlag != protocol.CommandKernelEchoRaw || !bytes.Contains(frame.Payload, []byte("[Fail]")) {
		t.Fatalf("malformed recv init rejection = %+v", frame)
	}
	// legacy recv 发起帧仍保持 fail-closed（未接入）。
	written.Reset()
	if err := bridge.Handle(protocol.Frame{ChannelID: 3, CommandFlag: protocol.CommandLegacyFileRecvInit}); err != nil {
		t.Fatalf("Handle(LegacyFileRecvInit) error = %v", err)
	}
	legacy := decodeWrittenFrame(t, codec, written.Bytes())
	if !bytes.Contains(legacy.Payload, []byte("not implemented")) {
		t.Fatalf("legacy recv rejection payload = %q", legacy.Payload)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) write(frame []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.buf.Write(frame)
	return err
}

func (b *syncBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

func (b *syncBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func (b *syncBuffer) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// waitNonEmpty 等待后台 goroutine 至少写出一帧。文件桥的 target 传输与 recv 回放
// 都在独立 goroutine 上执行，测试不能在 Handle 返回后立刻读缓冲。
func (b *syncBuffer) waitNonEmpty(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.len() > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for a frame to be written")
}

func TestFileBridgeDownloadsSingleFile(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	store, err := NewTempStore(filepath.Join(t.TempDir(), "transfers"), 1<<20)
	if err != nil {
		t.Fatalf("NewTempStore() error = %v", err)
	}
	content := []byte("device-file-body")
	openTarget := func(_ context.Context, command string) (TargetChannel, error) {
		fields := strings.Fields(command)
		tempPath := strings.Trim(fields[len(fields)-1], `"`)
		if writeErr := os.WriteFile(tempPath, content, 0o600); writeErr != nil {
			return nil, writeErr
		}
		return &fakeTargetChannel{}, nil
	}
	writer := &syncBuffer{}
	bridge := NewFileBridge(context.Background(), codec, store, 1<<20, time.Second, openTarget, writer.write)
	defer bridge.Close()

	// 真实负载：客户端追加 -cwd 选项（含带反斜杠的引号路径），路径为最后两个 token。
	initFrame := protocol.Frame{ChannelID: 9, CommandFlag: protocol.CommandFileInit, Payload: []byte(`-cwd "D:\work\" /data/local/tmp/a.txt ./a.txt`)}
	if err := bridge.Handle(initFrame); err != nil {
		t.Fatalf("Handle(FileInit) error = %v", err)
	}

	writer.waitNonEmpty(t)
	check := decodeWrittenFrame(t, codec, writer.snapshot())
	if check.CommandFlag != protocol.CommandFileCheck {
		t.Fatalf("expected CMD_FILE_CHECK, got %d", check.CommandFlag)
	}
	config, err := protocol.DecodeTransferConfig(check.Payload)
	if err != nil {
		t.Fatalf("DecodeTransferConfig() error = %v", err)
	}
	if config.FileSize != uint64(len(content)) || config.OptionalName != "a.txt" || config.Path != "./a.txt" {
		t.Fatalf("recv check config = %+v", config)
	}

	writer.reset()
	if err := bridge.Handle(protocol.Frame{ChannelID: 9, CommandFlag: protocol.CommandFileBegin}); err != nil {
		t.Fatalf("Handle(FileBegin) error = %v", err)
	}
	writer.waitNonEmpty(t)
	data := decodeWrittenFrame(t, codec, writer.snapshot())
	if data.CommandFlag != protocol.CommandFileData {
		t.Fatalf("expected CMD_FILE_DATA, got %d", data.CommandFlag)
	}
	header, body, err := protocol.DecodeTransferData(data.Payload, uint32(len(content)))
	if err != nil {
		t.Fatalf("DecodeTransferData() error = %v", err)
	}
	if header.Index != 0 || !bytes.Equal(body, content) {
		t.Fatalf("recv data header=%+v body=%q", header, body)
	}

	writer.reset()
	if err := bridge.Handle(protocol.Frame{ChannelID: 9, CommandFlag: protocol.CommandFileFinish, Payload: []byte{fileFinishCurrentFile}}); err != nil {
		t.Fatalf("Handle(FileFinish) error = %v", err)
	}
	finish := decodeWrittenFrame(t, codec, writer.snapshot())
	if finish.CommandFlag != protocol.CommandFileFinish || len(finish.Payload) != 1 || finish.Payload[0] != fileFinishAll {
		t.Fatalf("recv finish ack = %+v", finish)
	}
}

func decodeWrittenFrame(t *testing.T, codec *protocol.Codec, raw []byte) protocol.Frame {
	t.Helper()
	frameBytes, err := codec.ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	frame, err := codec.Decode(frameBytes)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return frame
}

type fakeTargetChannel struct {
	responses [][]byte
	command   string
}

func (f *fakeTargetChannel) ReadPayload() ([]byte, error) {
	if len(f.responses) == 0 {
		return nil, io.EOF
	}
	payload := f.responses[0]
	f.responses = f.responses[1:]
	if len(f.responses) == 0 {
		return payload, net.ErrClosed
	}
	return payload, nil
}

func (f *fakeTargetChannel) WritePayload([]byte) error { return nil }
func (f *fakeTargetChannel) Close() error              { return nil }
