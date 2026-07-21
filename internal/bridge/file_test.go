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
	bridge := NewFileBridge(context.Background(), codec, store, 1024, time.Second,
		func(context.Context, string) (TargetChannel, error) {
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
	deadline := time.Now().Add(time.Second)
	for writer.len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if writer.len() == 0 {
		t.Fatal("target upload produced no response")
	}
	if target.command != "file send" && target.command != "" {
		t.Fatalf("unexpected target command marker %q", target.command)
	}
	if _, err := os.Stat(tempRoot); err != nil {
		t.Fatalf("transfer root disappeared unexpectedly: %v", err)
	}
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

	deadline := time.Now().Add(time.Second)
	for writer.len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
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
