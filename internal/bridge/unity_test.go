package bridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestUnityCommandMappingUsesOfficialTargetCommands(t *testing.T) {
	tests := []struct {
		name    string
		command protocol.Command
		payload []byte
		target  string
		output  protocol.Command
	}{
		{name: "hilog", command: protocol.CommandUnityHilog, target: "hilog", output: protocol.CommandKernelEchoRaw},
		{name: "hilog help", command: protocol.CommandUnityHilog, payload: []byte("h"), target: "hilog -h", output: protocol.CommandKernelEchoRaw},
		{name: "jpid", command: protocol.CommandJDWPList, target: "jpid", output: protocol.CommandKernelEchoRaw},
		{name: "track default", command: protocol.CommandJDWPTrack, target: "track-jpid", output: protocol.CommandKernelEchoRaw},
		{name: "track debug", command: protocol.CommandJDWPTrack, payload: []byte("p"), target: "track-jpid -p", output: protocol.CommandKernelEchoRaw},
		{name: "track all", command: protocol.CommandJDWPTrack, payload: []byte("a"), target: "track-jpid -a", output: protocol.CommandKernelEchoRaw},
		{name: "bugreport", command: protocol.CommandUnityBugreportInit, target: "hidumper", output: commandUnityBugreportData},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, output, err := unityCommand(protocol.Frame{CommandFlag: test.command, Payload: test.payload})
			if err != nil {
				t.Fatalf("unityCommand() error = %v", err)
			}
			if target != test.target || output != test.output {
				t.Fatalf("unityCommand() = (%q, %d), want (%q, %d)", target, output, test.target, test.output)
			}
		})
	}
}

func TestUnityCommandRejectsPayloadOutsideOfficialBoundary(t *testing.T) {
	for _, test := range []struct {
		name    string
		command protocol.Command
		payload []byte
	}{
		{name: "hilog null", command: protocol.CommandUnityHilog, payload: []byte{0}},
		{name: "hilog extra", command: protocol.CommandUnityHilog, payload: []byte("help")},
		{name: "jpid payload", command: protocol.CommandJDWPList, payload: []byte("x")},
		{name: "track long", command: protocol.CommandJDWPTrack, payload: []byte("p ")},
		{name: "bugreport payload", command: protocol.CommandUnityBugreportInit, payload: []byte("bugreport")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := unityCommand(protocol.Frame{CommandFlag: test.command, Payload: test.payload}); err == nil {
				t.Fatal("unityCommand() error = nil")
			}
		})
	}
}

func TestUnityBridgeStreamsOutputWithMappedCommand(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	writer := newUnityFrameCollector(codec)
	var targetCommand string
	target := newUnityTarget([][]byte{[]byte("log line")}, false)
	bridge := NewUnityBridge(context.Background(), codec, time.Second,
		func(_ context.Context, command string) (TargetChannel, error) {
			targetCommand = command
			return target, nil
		}, writer.Write)

	if err := bridge.Handle(protocol.Frame{ChannelID: 11, CommandFlag: protocol.CommandUnityHilog, Payload: []byte("h")}); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	frames := writer.WaitFor(2, time.Second)
	bridge.Close()
	if targetCommand != "hilog -h" {
		t.Fatalf("target command = %q, want %q", targetCommand, "hilog -h")
	}
	if len(frames) != 2 {
		t.Fatalf("response frame count = %d, want 2", len(frames))
	}
	if frames[0].CommandFlag != protocol.CommandKernelEchoRaw || !bytes.Equal(frames[0].Payload, []byte("log line")) {
		t.Fatalf("output frame = %+v", frames[0])
	}
	if frames[1].CommandFlag != protocol.CommandKernelChannelClose {
		t.Fatalf("close frame command = %d", frames[1].CommandFlag)
	}
}

func TestUnityBridgeMapsBugreportOutputCommand(t *testing.T) {
	codec := protocol.NewCodec(1024 * 1024)
	writer := newUnityFrameCollector(codec)
	target := newUnityTarget([][]byte{[]byte("bugreport data")}, false)
	bridge := NewUnityBridge(context.Background(), codec, time.Second,
		func(_ context.Context, command string) (TargetChannel, error) {
			if command != "hidumper" {
				t.Fatalf("target command = %q, want hidumper", command)
			}
			return target, nil
		}, writer.Write)

	if err := bridge.Handle(protocol.Frame{ChannelID: 12, CommandFlag: protocol.CommandUnityBugreportInit}); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	frames := writer.WaitFor(2, time.Second)
	bridge.Close()
	if len(frames) != 2 {
		t.Fatalf("response frame count = %d, want 2", len(frames))
	}
	if frames[0].CommandFlag != commandUnityBugreportData || !bytes.Equal(frames[0].Payload, []byte("bugreport data")) {
		t.Fatalf("bugreport frame = %+v", frames[0])
	}
}

func TestUnityBridgeRejectsInvalidRequestWithErrorAndClose(t *testing.T) {
	codec := protocol.NewCodec(4096)
	writer := newUnityFrameCollector(codec)
	bridge := NewUnityBridge(context.Background(), codec, time.Second, nil, writer.Write)

	if err := bridge.Handle(protocol.Frame{ChannelID: 13, CommandFlag: protocol.CommandJDWPTrack, Payload: []byte("p ")}); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	frames := writer.WaitFor(2, time.Second)
	bridge.Close()
	if len(frames) != 2 {
		t.Fatalf("response frame count = %d, want 2", len(frames))
	}
	if frames[0].CommandFlag != protocol.CommandKernelEchoRaw || !bytes.Contains(frames[0].Payload, []byte("invalid")) {
		t.Fatalf("error frame = %+v", frames[0])
	}
	if frames[1].CommandFlag != protocol.CommandKernelChannelClose {
		t.Fatalf("close frame command = %d", frames[1].CommandFlag)
	}
}

func TestUnityBridgeTimeoutClosesTargetChannel(t *testing.T) {
	codec := protocol.NewCodec(4096)
	writer := newUnityFrameCollector(codec)
	target := newUnityTarget(nil, true)
	bridge := NewUnityBridge(context.Background(), codec, 20*time.Millisecond,
		func(_ context.Context, _ string) (TargetChannel, error) { return target, nil }, writer.Write)

	if err := bridge.Handle(protocol.Frame{ChannelID: 14, CommandFlag: protocol.CommandJDWPTrack, Payload: []byte("p")}); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	frames := writer.WaitFor(2, time.Second)
	bridge.Close()
	if len(frames) != 2 || !bytes.Contains(frames[0].Payload, []byte("timed out")) {
		t.Fatalf("timeout responses = %+v", frames)
	}
	if !target.IsClosed() {
		t.Fatal("target channel was not closed after timeout")
	}
}

func TestUnityBridgeCloseCancelsActiveStream(t *testing.T) {
	codec := protocol.NewCodec(4096)
	writer := newUnityFrameCollector(codec)
	target := newUnityTarget(nil, true)
	bridge := NewUnityBridge(context.Background(), codec, time.Minute,
		func(_ context.Context, _ string) (TargetChannel, error) { return target, nil }, writer.Write)

	if err := bridge.Handle(protocol.Frame{ChannelID: 15, CommandFlag: protocol.CommandJDWPList}); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	bridge.Close()
	if !target.IsClosed() {
		t.Fatal("target channel was not closed")
	}
}

type unityFrameCollector struct {
	codec *protocol.Codec

	mu     sync.Mutex
	frames []protocol.Frame
	notify chan struct{}
}

func newUnityFrameCollector(codec *protocol.Codec) *unityFrameCollector {
	return &unityFrameCollector{codec: codec, notify: make(chan struct{}, 16)}
}

func (c *unityFrameCollector) Write(raw []byte) error {
	reader := bytes.NewReader(raw)
	for reader.Len() > 0 {
		frameBytes, err := c.codec.ReadFrame(reader)
		if err != nil {
			return err
		}
		frame, err := c.codec.Decode(frameBytes)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.frames = append(c.frames, frame)
		c.mu.Unlock()
		c.notify <- struct{}{}
	}
	return nil
}

func (c *unityFrameCollector) WaitFor(count int, timeout time.Duration) []protocol.Frame {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		if len(c.frames) >= count {
			result := append([]protocol.Frame(nil), c.frames...)
			c.mu.Unlock()
			return result
		}
		c.mu.Unlock()
		select {
		case <-c.notify:
		case <-deadline.C:
			c.mu.Lock()
			result := append([]protocol.Frame(nil), c.frames...)
			c.mu.Unlock()
			return result
		}
	}
}

type unityTarget struct {
	responses [][]byte
	block     bool
	closed    chan struct{}
	closeOnce sync.Once
}

func newUnityTarget(responses [][]byte, block bool) *unityTarget {
	return &unityTarget{responses: responses, block: block, closed: make(chan struct{})}
}

func (t *unityTarget) ReadPayload() ([]byte, error) {
	if len(t.responses) > 0 {
		payload := t.responses[0]
		t.responses = t.responses[1:]
		if len(t.responses) == 0 && !t.block {
			return payload, io.EOF
		}
		return payload, nil
	}
	if t.block {
		<-t.closed
		return nil, net.ErrClosed
	}
	return nil, io.EOF
}

func (t *unityTarget) WritePayload([]byte) error { return nil }

func (t *unityTarget) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func (t *unityTarget) IsClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
