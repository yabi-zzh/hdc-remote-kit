package hostauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Decision 是操作者对一条 pending 请求的裁决。
type Decision string

const (
	DecisionAllowOnce    Decision = "allow_once"
	DecisionAllowForever Decision = "allow_forever"
	DecisionDeny         Decision = "deny"
	DecisionExpired      Decision = "expired"
)

// ErrNotFound 表示没有匹配的 pending 或已信任指纹。
var ErrNotFound = errors.New("host auth request not found")

// PendingRequest 是一条待本机确认的远程公钥请求（不含 PEM）。
type PendingRequest struct {
	RequestID   string    `json:"request_id"`
	DeviceID    string    `json:"device_id"`
	Serial      string    `json:"serial"`
	Hostname    string    `json:"hostname"`
	Fingerprint string    `json:"fingerprint"`
	SourceIP    string    `json:"source_ip"`
	LeaseID     string    `json:"lease_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// KnownHost 是已永久信任的远程 hdc 公钥指纹。
type KnownHost struct {
	Fingerprint string    `json:"fingerprint"`
	Hostname    string    `json:"hostname"`
	CreatedAt   time.Time `json:"created_at"`
}

// RecentEvent 是本进程内最近一次授权操作，供确认台展示，不落盘。
type RecentEvent struct {
	At          time.Time `json:"at"`
	Action      string    `json:"action"`
	Hostname    string    `json:"hostname"`
	Fingerprint string    `json:"fingerprint"`
	SourceIP    string    `json:"source_ip,omitempty"`
	Serial      string    `json:"serial,omitempty"`
}

const NoticeClientVersionTooOld = "client_version_too_old"

// Notice 是给本机确认台看的握手失败提示，不可裁决，不落盘。
type Notice struct {
	NoticeID  string    `json:"notice_id"`
	Kind      string    `json:"kind"`
	Serial    string    `json:"serial,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Version   string    `json:"version,omitempty"`
	Required  string    `json:"required,omitempty"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

const maxRecentEvents = 20

type pendingWaiter struct {
	PendingRequest
	result chan Decision
}

// Registry 持有 known_hosts 与进程内 pending；裁决口给确认台调用，日志只打印同一条事件。
type Registry struct {
	path           string
	confirmTimeout time.Duration
	logger         *slog.Logger
	now            func() time.Time
	mu             sync.Mutex
	hosts          map[string]KnownHost
	pending        map[string]*pendingWaiter
	recent         []RecentEvent
	notices        []Notice
	suppressed     map[string]time.Time
	saveMu         sync.Mutex
}

// NewRegistry 从 stateDir/known_hosts.json 恢复白名单。
func NewRegistry(stateDir string, confirmTimeout time.Duration, logger *slog.Logger) (*Registry, error) {
	if confirmTimeout <= 0 {
		confirmTimeout = 90 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	registry := &Registry{
		path:           filepath.Join(stateDir, "known_hosts.json"),
		confirmTimeout: confirmTimeout,
		logger:         logger,
		now:            time.Now,
		hosts:          make(map[string]KnownHost),
		pending:        make(map[string]*pendingWaiter),
		suppressed:     make(map[string]time.Time),
	}
	hosts, err := loadKnownHosts(registry.path)
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		registry.hosts[host.Fingerprint] = host
	}
	return registry, nil
}

// Trusted 判定指纹是否已永久放行。
func (r *Registry) Trusted(fingerprint string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.hosts[strings.TrimSpace(fingerprint)]
	return ok
}

// Submit 在白名单命中时立即放行；否则挂起直到裁决或超时。不把 PEM 写入 pending 视图。
func (r *Registry) Submit(ctx context.Context, request PendingRequest) (Decision, error) {
	request.Fingerprint = strings.TrimSpace(request.Fingerprint)
	if request.Fingerprint == "" {
		return DecisionDeny, fmt.Errorf("host fingerprint is required")
	}
	now := r.now().UTC()
	if request.CreatedAt.IsZero() {
		request.CreatedAt = now
	}
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = now.Add(r.confirmTimeout)
	}
	if request.RequestID == "" {
		request.RequestID = newID()
	}

	r.mu.Lock()
	if _, trusted := r.hosts[request.Fingerprint]; trusted {
		r.mu.Unlock()
		return DecisionAllowForever, nil
	}
	waiter := &pendingWaiter{PendingRequest: request, result: make(chan Decision, 1)}
	r.pending[request.RequestID] = waiter
	r.mu.Unlock()

	r.logger.Info("auth pending",
		"serial", request.Serial,
		"host", request.Hostname,
		"fingerprint", ShortFingerprint(request.Fingerprint),
		"source", request.SourceIP,
		"request_id", request.RequestID)

	timer := time.NewTimer(time.Until(request.ExpiresAt))
	defer timer.Stop()
	var decision Decision
	select {
	case decision = <-waiter.result:
	case <-ctx.Done():
		decision = DecisionDeny
	case <-timer.C:
		decision = DecisionExpired
	}
	r.mu.Lock()
	delete(r.pending, request.RequestID)
	r.mu.Unlock()
	if decision == "" {
		decision = DecisionDeny
	}
	if decision == DecisionExpired {
		r.Record(RecentEvent{
			Action: string(decision), Hostname: request.Hostname, Fingerprint: request.Fingerprint,
			SourceIP: request.SourceIP, Serial: request.Serial,
		})
	}
	return decision, nil
}

// Decide 按 request_id 或指纹前缀裁决一条 pending。forever 会写入 known_hosts。
func (r *Registry) Decide(selector string, decision Decision) error {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return fmt.Errorf("auth request selector is required")
	}
	if decision != DecisionAllowOnce && decision != DecisionAllowForever && decision != DecisionDeny {
		return fmt.Errorf("invalid auth decision")
	}
	r.mu.Lock()
	waiter := r.pending[selector]
	if waiter == nil {
		for _, candidate := range r.pending {
			if fingerprintMatch(candidate.Fingerprint, selector) {
				waiter = candidate
				break
			}
		}
	}
	if waiter == nil {
		r.mu.Unlock()
		return ErrNotFound
	}
	if decision == DecisionAllowForever {
		host := KnownHost{
			Fingerprint: waiter.Fingerprint,
			Hostname:    waiter.Hostname,
			CreatedAt:   r.now().UTC(),
		}
		r.hosts[host.Fingerprint] = host
		hosts := r.hostListLocked()
		r.mu.Unlock()
		if err := r.save(hosts); err != nil {
			return err
		}
	} else {
		r.mu.Unlock()
	}
	select {
	case waiter.result <- decision:
	default:
	}
	r.Record(RecentEvent{
		Action: string(decision), Hostname: waiter.Hostname, Fingerprint: waiter.Fingerprint,
		SourceIP: waiter.SourceIP, Serial: waiter.Serial,
	})
	r.logger.Info("auth decided",
		"decision", string(decision),
		"host", waiter.Hostname,
		"fingerprint", ShortFingerprint(waiter.Fingerprint),
		"request_id", waiter.RequestID)
	return nil
}

// Pending 返回当前待确认请求的副本。
func (r *Registry) Pending() []PendingRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()
	result := make([]PendingRequest, 0, len(r.pending))
	for _, waiter := range r.pending {
		if now.After(waiter.ExpiresAt) {
			continue
		}
		result = append(result, waiter.PendingRequest)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

// Keys 返回已信任指纹列表。
func (r *Registry) Keys() []KnownHost {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hostListLocked()
}

// Revoke 删除已信任指纹；已建立的连接不在这里断开。
func (r *Registry) Revoke(fingerprint string) error {
	fingerprint = strings.TrimSpace(fingerprint)
	r.mu.Lock()
	matched := ""
	if _, ok := r.hosts[fingerprint]; ok {
		matched = fingerprint
	} else {
		for stored := range r.hosts {
			if fingerprintMatch(stored, fingerprint) {
				if matched != "" {
					r.mu.Unlock()
					return fmt.Errorf("fingerprint prefix matches more than one key")
				}
				matched = stored
			}
		}
	}
	if matched == "" {
		r.mu.Unlock()
		return ErrNotFound
	}
	revoked := r.hosts[matched]
	delete(r.hosts, matched)
	hosts := r.hostListLocked()
	r.mu.Unlock()
	r.Record(RecentEvent{Action: "revoke", Hostname: revoked.Hostname, Fingerprint: matched})
	return r.save(hosts)
}

// Recent 返回本进程内最近授权操作，新的在前。
func (r *Registry) Recent() []RecentEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]RecentEvent, len(r.recent))
	copy(result, r.recent)
	return result
}

// Notify 写入一条确认台提示；同 kind+来源+设备去重，只刷新时间与文案。
func (r *Registry) Notify(notice Notice) {
	if strings.TrimSpace(notice.Kind) == "" {
		return
	}
	now := r.now().UTC()
	if notice.CreatedAt.IsZero() {
		notice.CreatedAt = now
	}
	if notice.ExpiresAt.IsZero() {
		notice.ExpiresAt = now.Add(r.confirmTimeout)
	}
	if notice.NoticeID == "" {
		notice.NoticeID = newID()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneNoticesLocked(now)
	if until, ok := r.suppressed[noticeDedupeKey(notice)]; ok && now.Before(until) {
		return
	}
	for i, existing := range r.notices {
		if existing.Kind == notice.Kind && existing.SourceIP == notice.SourceIP && existing.Serial == notice.Serial {
			notice.NoticeID = existing.NoticeID
			r.notices[i] = notice
			return
		}
	}
	r.notices = append([]Notice{notice}, r.notices...)
	if len(r.notices) > maxRecentEvents {
		r.notices = r.notices[:maxRecentEvents]
	}
}

// Notices 返回未过期的握手提示，新的在前。
func (r *Registry) Notices() []Notice {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()
	r.pruneNoticesLocked(now)
	result := make([]Notice, len(r.notices))
	copy(result, r.notices)
	return result
}

// DismissNotice 关掉一条提示；同一来源在确认超时内不再刷出。
func (r *Registry) DismissNotice(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("notice id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, notice := range r.notices {
		if notice.NoticeID != id {
			continue
		}
		r.notices = append(r.notices[:i], r.notices[i+1:]...)
		r.suppressed[noticeDedupeKey(notice)] = r.now().UTC().Add(r.confirmTimeout)
		return nil
	}
	return ErrNotFound
}

func (r *Registry) pruneNoticesLocked(now time.Time) {
	kept := r.notices[:0]
	for _, notice := range r.notices {
		if now.Before(notice.ExpiresAt) {
			kept = append(kept, notice)
		}
	}
	r.notices = kept
	for key, until := range r.suppressed {
		if !now.Before(until) {
			delete(r.suppressed, key)
		}
	}
}

func noticeDedupeKey(notice Notice) string {
	return notice.Kind + "\x1f" + notice.SourceIP + "\x1f" + notice.Serial
}

// Record 追加一条最近操作。
func (r *Registry) Record(event RecentEvent) {
	if event.Action == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if event.At.IsZero() {
		event.At = r.now().UTC()
	}
	r.recent = append([]RecentEvent{event}, r.recent...)
	if len(r.recent) > maxRecentEvents {
		r.recent = r.recent[:maxRecentEvents]
	}
}

func (r *Registry) hostListLocked() []KnownHost {
	hosts := make([]KnownHost, 0, len(r.hosts))
	for _, host := range r.hosts {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].CreatedAt.Before(hosts[j].CreatedAt) })
	return hosts
}

func (r *Registry) save(hosts []KnownHost) error {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	return writeKnownHosts(r.path, hosts)
}

func fingerprintMatch(stored, selector string) bool {
	stored = strings.TrimSpace(stored)
	selector = strings.TrimSpace(selector)
	if stored == "" || selector == "" {
		return false
	}
	return stored == selector || strings.HasPrefix(stored, selector)
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
