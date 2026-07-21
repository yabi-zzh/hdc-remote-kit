// Package audit 提供结构化命令审计：以独立 goroutine 非阻塞地把每条命令决策追加写入 JSONL 安全日志。
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

const (
	auditFileName = "audit.jsonl"
	eventBuffer   = 4096
)

// Recorder 是审计写入端契约，供 gateway 在命令主链路上调用。
// 实现必须非阻塞：写入失败或积压只能丢弃并计错误指标，绝不能阻塞协议链路。
type Recorder interface {
	Record(event model.Audit)
}

// Sink 以独立 goroutine 把审计事件追加落盘到 JSONL 文件。
type Sink struct {
	events  chan model.Audit
	done    chan struct{}
	flushed chan struct{}
	file    *os.File
	logger  *slog.Logger

	closeOnce sync.Once

	dropped uint64
	failed  uint64
}

// NewSink 打开 stateDir 下的审计文件并启动后台写入 goroutine。
func NewSink(stateDir string, logger *slog.Logger) (*Sink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create audit state dir %q: %w", stateDir, err)
	}
	path := filepath.Join(stateDir, auditFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file %q: %w", path, err)
	}
	sink := &Sink{
		events:  make(chan model.Audit, eventBuffer),
		done:    make(chan struct{}),
		flushed: make(chan struct{}),
		file:    file,
		logger:  logger,
	}
	go sink.loop()
	return sink, nil
}

// Record 非阻塞提交一条审计事件；队列积压或已关闭时丢弃并累加指标。
func (s *Sink) Record(event model.Audit) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	select {
	case <-s.done:
		atomic.AddUint64(&s.dropped, 1)
	case s.events <- event:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

// Close 停止后台写入，落盘剩余事件并关闭文件。
func (s *Sink) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	<-s.flushed
	if dropped := atomic.LoadUint64(&s.dropped); dropped > 0 {
		s.logger.Warn("audit events dropped", "count", dropped)
	}
	if failed := atomic.LoadUint64(&s.failed); failed > 0 {
		s.logger.Warn("audit events failed to persist", "count", failed)
	}
	return nil
}

func (s *Sink) loop() {
	defer close(s.flushed)
	for {
		select {
		case event := <-s.events:
			s.persist(event)
		case <-s.done:
			// 关闭时排空剩余事件，Sync 后关闭文件。
			for {
				select {
				case event := <-s.events:
					s.persist(event)
				default:
					_ = s.file.Sync()
					_ = s.file.Close()
					return
				}
			}
		}
	}
}

func (s *Sink) persist(event model.Audit) {
	line, err := json.Marshal(event)
	if err != nil {
		atomic.AddUint64(&s.failed, 1)
		s.logger.Error("audit event marshal failed", "error", err)
		return
	}
	line = append(line, '\n')
	if _, err := s.file.Write(line); err != nil {
		atomic.AddUint64(&s.failed, 1)
		s.logger.Error("audit event write failed", "error", err)
	}
}
