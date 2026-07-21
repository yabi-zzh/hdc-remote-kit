package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

const commandUnityBugreportData protocol.Command = 1012

const (
	failUnityInvalidRequest = "[Fail] Unity request is invalid."
	failUnityCommand        = "[Fail] Unity command failed."
	failUnityTimeout        = "[Fail] Unity command timed out."
	failUnityUnsupported    = "[Fail] Unity command is not supported."
)

// UnityBridge 处理 unity 族流式命令（hilog / jpid / track-jpid / bugreport）：
// 把命令字符串交主 HDC 执行，将设备输出按各命令约定的输出帧（EchoRaw 或 BugreportData）回推 client。
type UnityBridge struct {
	ctx        context.Context
	codec      *protocol.Codec
	timeout    time.Duration
	openTarget OpenTargetFunc
	write      FrameWriter

	mu      sync.Mutex
	streams map[uint32]*unityStream
	closed  bool
	closeWg sync.WaitGroup
}

// NewUnityBridge 构造 unity 族流式桥接（hilog/jpid/track-jpid/bugreport）；timeout 控制单条流的最长存活。
func NewUnityBridge(ctx context.Context, codec *protocol.Codec, timeout time.Duration, openTarget OpenTargetFunc, write FrameWriter) *UnityBridge {
	return &UnityBridge{
		ctx: ctx, codec: codec, timeout: timeout, openTarget: openTarget, write: write,
		streams: make(map[uint32]*unityStream),
	}
}

// Handle 解析 unity 命令并启动独立流式 target channel，把设备输出按各命令约定的帧回推 client。
func (b *UnityBridge) Handle(frame protocol.Frame) error {
	command, outputCommand, err := unityCommand(frame)
	if err != nil {
		return b.reject(frame.ChannelID, err.Error())
	}
	b.mu.Lock()
	if b.closed || b.streams[frame.ChannelID] != nil {
		b.mu.Unlock()
		return b.reject(frame.ChannelID, failUnityInvalidRequest)
	}
	stream := &unityStream{
		channelID:     frame.ChannelID,
		command:       command,
		outputCommand: outputCommand,
		owner:         b,
	}
	b.streams[frame.ChannelID] = stream
	b.closeWg.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.closeWg.Done()
		b.runStream(stream)
	}()
	return nil
}

// CloseChannel 关闭指定 channel 上的流式会话（收到 ChannelClose 时调用）。
func (b *UnityBridge) CloseChannel(channelID uint32) {
	b.mu.Lock()
	stream := b.streams[channelID]
	delete(b.streams, channelID)
	b.mu.Unlock()
	if stream != nil {
		stream.close()
	}
}

// Close 关闭 unity 桥：关闭所有流式 target channel 并等待其 goroutine 退出。
func (b *UnityBridge) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	streams := make([]*unityStream, 0, len(b.streams))
	for channelID, stream := range b.streams {
		streams = append(streams, stream)
		delete(b.streams, channelID)
	}
	b.mu.Unlock()
	for _, stream := range streams {
		stream.close()
	}
	b.closeWg.Wait()
}

func (b *UnityBridge) runStream(stream *unityStream) {
	ctx, cancel := context.WithTimeout(b.ctx, b.timeout)
	defer cancel()
	if b.openTarget == nil {
		b.finishStream(stream, failUnityCommand)
		return
	}

	target, err := b.openTarget(ctx, stream.command)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			b.finishStream(stream, failUnityTimeout)
		} else {
			b.finishStream(stream, failUnityCommand)
		}
		return
	}
	if !stream.attachTarget(target) {
		_ = target.Close()
		return
	}

	// TargetChannel 的读取是阻塞式的；超时必须关闭底层 channel，不能只依赖 context。
	readDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stream.close()
		case <-readDone:
		}
	}()
	defer close(readDone)

	for {
		payload, readErr := target.ReadPayload()
		if len(payload) > 0 {
			if err := b.write(b.codec.EncodeFrame(stream.channelID, stream.outputCommand, payload)); err != nil {
				b.finishStream(stream, "")
				return
			}
		}
		if readErr != nil {
			switch {
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				b.finishStream(stream, failUnityTimeout)
			case errors.Is(readErr, io.EOF), errors.Is(readErr, net.ErrClosed):
				b.finishStream(stream, "")
			default:
				b.finishStream(stream, failUnityCommand)
			}
			return
		}
	}
}

func (b *UnityBridge) finishStream(stream *unityStream, message string) {
	b.mu.Lock()
	if b.streams[stream.channelID] != stream {
		b.mu.Unlock()
		return
	}
	delete(b.streams, stream.channelID)
	b.mu.Unlock()
	stream.close()
	if message != "" {
		_ = b.write(b.codec.EncodeEchoRaw(stream.channelID, []byte(message+"\n")))
	}
	_ = b.write(b.codec.EncodeChannelClose(stream.channelID))
}

func (b *UnityBridge) reject(channelID uint32, message string) error {
	return b.write(b.codec.EncodeEchoAndClose(channelID, message))
}

type unityStream struct {
	channelID     uint32
	command       string
	outputCommand protocol.Command
	owner         *UnityBridge

	mu        sync.Mutex
	target    TargetChannel
	closed    bool
	closeOnce sync.Once
}

func (s *unityStream) attachTarget(target TargetChannel) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.target = target
	return true
}

func (s *unityStream) close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		target := s.target
		s.target = nil
		s.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
	})
}

func unityCommand(frame protocol.Frame) (string, protocol.Command, error) {
	switch frame.CommandFlag {
	case protocol.CommandUnityHilog:
		if len(frame.Payload) == 0 {
			return "hilog", protocol.CommandKernelEchoRaw, nil
		}
		if len(frame.Payload) == 1 && frame.Payload[0] == 'h' {
			return "hilog -h", protocol.CommandKernelEchoRaw, nil
		}
		return "", 0, fmt.Errorf("%s", failUnityInvalidRequest)
	case protocol.CommandJDWPList:
		if len(frame.Payload) != 0 {
			return "", 0, fmt.Errorf("%s", failUnityInvalidRequest)
		}
		return "jpid", protocol.CommandKernelEchoRaw, nil
	case protocol.CommandJDWPTrack:
		// 无 payload 为默认（track-jpid）；单字节 p/a 分别映射 -p/-a。
		if len(frame.Payload) == 0 {
			return "track-jpid", protocol.CommandKernelEchoRaw, nil
		}
		if len(frame.Payload) == 1 && (frame.Payload[0] == 'p' || frame.Payload[0] == 'a') {
			return "track-jpid -" + string(frame.Payload), protocol.CommandKernelEchoRaw, nil
		}
		return "", 0, fmt.Errorf("%s", failUnityInvalidRequest)
	case protocol.CommandUnityBugreportInit:
		if len(frame.Payload) != 0 {
			return "", 0, fmt.Errorf("%s", failUnityInvalidRequest)
		}
		return "hidumper", commandUnityBugreportData, nil
	default:
		return "", 0, fmt.Errorf("%s", failUnityUnsupported)
	}
}
