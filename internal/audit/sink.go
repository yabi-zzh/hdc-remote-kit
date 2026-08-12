// Package audit 提供结构化命令审计：以独立 goroutine 非阻塞地把每条命令决策追加写入 JSONL 安全日志。
package audit

import (
	"encoding/json"
	"errors"
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
	// maxAuditBytes 是单个审计文件的大小上限，超过即轮转为 .1（只保留一代）。
	// 常驻进程持有同一个句柄且从不轮转的话，文件会一直涨到把状态分区写满。
	maxAuditBytes = 64 * 1024 * 1024
	// dropReportInterval 限制丢弃告警的频率：只在 Close 时汇报的话，
	// 运行中审计出现缺口时运维完全无从察觉。
	dropReportInterval = time.Minute
	// rotationRetryInterval 是轮转失败后的冷却时间，避免持续失败时每条事件都重试。
	rotationRetryInterval = time.Minute
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
	path    string
	logger  *slog.Logger

	closeOnce sync.Once
	closed    atomic.Bool

	// 以下字段只在后台 goroutine 内访问。
	file            *os.File
	written         int64
	closeErr        error
	lastDropNotic   time.Time
	reportedDropped uint64
	rotateRetryAt   time.Time

	dropped uint64
	failed  uint64
}

// NewSink 打开 stateDir 下的审计文件并启动后台写入 goroutine。
func NewSink(stateDir string, logger *slog.Logger) (*Sink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	// 审计记录含设备与来源信息，状态目录不应对其他本地用户可读。
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create audit state dir %q: %w", stateDir, err)
	}
	path := filepath.Join(stateDir, auditFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file %q: %w", path, err)
	}
	var written int64
	if info, statErr := file.Stat(); statErr == nil {
		written = info.Size()
	}
	sink := &Sink{
		events:  make(chan model.Audit, eventBuffer),
		done:    make(chan struct{}),
		flushed: make(chan struct{}),
		path:    path,
		logger:  logger,
		file:    file,
		written: written,
	}
	go sink.loop()
	return sink, nil
}

// Record 非阻塞提交一条审计事件；队列积压或已关闭时丢弃并累加指标。
func (s *Sink) Record(event model.Audit) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	// 先单独判定已关闭：与下面的发送写在同一个 select 里的话，
	// done 已关闭时两个 case 同时就绪，Go 会随机挑一个，
	// 约一半的记录会被投进没人再读的 channel，且不计入 dropped。
	// 这里只是把窗口收窄到「判定后被抢占」这一瞬，并非完全消除。
	if s.closed.Load() {
		atomic.AddUint64(&s.dropped, 1)
		return
	}
	select {
	case s.events <- event:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

// Close 停止后台写入，落盘剩余事件并关闭文件。
// 只要有记录没能落盘（写失败、轮转后重开失败、Sync/Close 失败）就返回错误：
// 审计缺口必须留下痕迹，报告成功等于把它彻底掩盖。
func (s *Sink) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
	})
	<-s.flushed

	var closeErrors []error
	if s.closeErr != nil {
		closeErrors = append(closeErrors, s.closeErr)
	}
	if dropped := atomic.LoadUint64(&s.dropped); dropped > 0 {
		s.logger.Warn("audit events dropped", "count", dropped)
		closeErrors = append(closeErrors, fmt.Errorf("%d audit events were dropped", dropped))
	}
	if failed := atomic.LoadUint64(&s.failed); failed > 0 {
		s.logger.Warn("audit events failed to persist", "count", failed)
		closeErrors = append(closeErrors, fmt.Errorf("%d audit events failed to persist", failed))
	}
	return errors.Join(closeErrors...)
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
					if s.file != nil {
						s.closeErr = errors.Join(s.file.Sync(), s.file.Close())
						s.file = nil
					}
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
	s.rotateIfNeeded(int64(len(line)))
	if s.file == nil {
		atomic.AddUint64(&s.failed, 1)
		return
	}
	written, err := s.file.Write(line)
	s.written += int64(written)
	if err != nil {
		atomic.AddUint64(&s.failed, 1)
		s.logger.Error("audit event write failed", "error", err)
	}
	s.reportDropped()
}

// rotateIfNeeded 在写入会超过上限时把当前文件转为 .1 并重开，只保留一代历史。
//
// 每一步都必须先确认成功再推进状态：先删 .1 再 rename 的话，
// 一旦 rename 或重开失败，下一条事件会再次进来把刚轮转出去的那一代删掉，
// 相当于一次瞬时失败就抹掉全部审计历史。
func (s *Sink) rotateIfNeeded(incoming int64) {
	if s.file == nil || s.written+incoming <= maxAuditBytes {
		return
	}
	// 轮转失败后冷却一段时间再试，避免持续失败时每条事件都重试一轮系统调用。
	now := time.Now()
	if !s.rotateRetryAt.IsZero() && now.Before(s.rotateRetryAt) {
		return
	}
	s.rotateRetryAt = time.Time{}
	if err := errors.Join(s.file.Sync(), s.file.Close()); err != nil {
		s.logger.Error("audit rotation failed to close current file", "error", err)
	}
	s.file = nil

	rotated := s.path + ".1"
	renamed := true
	if err := os.Rename(s.path, rotated); err != nil {
		// 轮转失败时保留旧的 .1：它是仅存的历史，不能因为本次失败而丢掉。
		renamed = false
		s.logger.Error("audit rotation failed", "error", err)
	}

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.logger.Error("audit rotation failed to reopen", "error", err)
		s.rotateRetryAt = now.Add(rotationRetryInterval)
		return
	}
	s.file = file
	if renamed {
		s.written = 0
		s.logger.Info("audit log rotated", "rotated_to", rotated)
		return
	}
	// rename 失败时重开的仍是同一个文件，必须按真实大小续记，
	// 否则计数归零会让它继续无限增长。
	s.written = 0
	if info, statErr := file.Stat(); statErr == nil {
		s.written = info.Size()
	}
	s.rotateRetryAt = now.Add(rotationRetryInterval)
}

// reportDropped 周期性汇报丢弃数，使运行期出现的审计缺口能被及时发现。
// count 为本间隔内新增的丢弃数，total 为进程累计值。
func (s *Sink) reportDropped() {
	dropped := atomic.LoadUint64(&s.dropped)
	if dropped == s.reportedDropped {
		return
	}
	now := time.Now()
	if !s.lastDropNotic.IsZero() && now.Sub(s.lastDropNotic) < dropReportInterval {
		return
	}
	s.lastDropNotic = now
	s.logger.Warn("audit events dropped", "count", dropped-s.reportedDropped, "total", dropped)
	s.reportedDropped = dropped
}
