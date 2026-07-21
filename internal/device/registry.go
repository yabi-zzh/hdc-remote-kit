// Package device 维护设备事实的后台快照：由轮询循环独占刷新，读方只取快照、绝不触发扫描，
// 并用 stale 去抖避免瞬时扫描失败把设备误判为离线。
package device

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

// ErrRegistryNotReady 表示 Registry 尚未完成首次成功扫描，此时快照不可用。
var ErrRegistryNotReady = errors.New("device registry has not completed a successful scan")

// Scanner 是设备扫描契约，由 hdc.HostClient 实现（执行 list targets）。
type Scanner interface {
	ListTargets(ctx context.Context) ([]model.Device, error)
}

// Registry 维护设备事实的后台快照：由 Run 的 poll ticker 独占刷新，读方只取快照、绝不触发扫描。
// 扫描失败时保留上次成功快照并计 stale 时间，连续超过 staleAfter 才把设备降级为 UNKNOWN，避免瞬时抖动误判离线。
type Registry struct {
	scanner      Scanner
	pollInterval time.Duration
	staleAfter   time.Duration
	logger       *slog.Logger
	now          func() time.Time

	mu          sync.RWMutex
	devices     map[string]model.Device
	lastSuccess time.Time
	ready       bool
}

// NewRegistry 构造设备注册表；pollInterval 为扫描周期，staleAfter 为判定快照过期的阈值。
func NewRegistry(scanner Scanner, pollInterval, staleAfter time.Duration, logger *slog.Logger) *Registry {
	return &Registry{
		scanner: scanner, pollInterval: pollInterval, staleAfter: staleAfter,
		logger: logger, now: time.Now, devices: make(map[string]model.Device),
	}
}

// Run 独占设备轮询循环：启动即先扫描一次，之后按 pollInterval 周期刷新，直到 ctx 取消。
// 调用方只读取快照，绝不自行触发 HDC 扫描。
func (r *Registry) Run(ctx context.Context) {
	r.refresh(ctx)
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refresh(ctx)
		}
	}
}

// Devices 返回按 ID 排序的设备快照；首次成功扫描前返回 ErrRegistryNotReady。
func (r *Registry) Devices() ([]model.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.ready {
		return nil, ErrRegistryNotReady
	}
	return snapshot(r.devices), nil
}

// Find 按内部 deviceID 查找，未命中再按 connectKey 兜底匹配。
func (r *Registry) Find(identifier string) (model.Device, bool) {
	identifier = strings.TrimSpace(identifier)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if device, ok := r.devices[identifier]; ok {
		return device, true
	}
	for _, device := range r.devices {
		if device.ConnectKey == identifier {
			return device, true
		}
	}
	return model.Device{}, false
}

// ResolveOnlineUSB 仅当设备为在线 USB 且有 connectKey 时返回；否则报错。远程租约只允许此类设备。
func (r *Registry) ResolveOnlineUSB(deviceID string) (model.Device, error) {
	device, found := r.Find(deviceID)
	if !found || device.Transport != model.TransportUSB || device.Status != model.TargetOnline || strings.TrimSpace(device.ConnectKey) == "" {
		return model.Device{}, fmt.Errorf("device %q is not an online USB target", deviceID)
	}
	return device, nil
}

// Ready 返回是否已完成至少一次成功扫描（供 readiness 判断）。
func (r *Registry) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready
}

func (r *Registry) refresh(ctx context.Context) {
	visible, err := r.scanner.ListTargets(ctx)
	now := r.now().UTC()
	if err != nil {
		r.markStale(now)
		r.logger.Warn("HDC device scan failed", "error", err)
		return
	}

	next := make(map[string]model.Device, len(visible))
	for _, device := range visible {
		if strings.TrimSpace(device.ID) == "" {
			continue
		}
		device.UpdatedAt = now
		next[device.ID] = device
	}

	r.mu.Lock()
	for deviceID, previous := range r.devices {
		if _, exists := next[deviceID]; exists {
			continue
		}
		previous.Status = model.TargetOffline
		previous.UpdatedAt = now
		next[deviceID] = previous
	}
	changed := !sameDeviceSnapshot(r.devices, next)
	r.devices = next
	r.lastSuccess = now
	firstSuccess := !r.ready
	r.ready = true
	r.mu.Unlock()

	if firstSuccess {
		r.logger.Info("device registry ready", "devices", len(next))
		return
	}
	if changed {
		r.logger.Debug("device snapshot changed", "devices", len(next))
	}
}

func sameDeviceSnapshot(previous, next map[string]model.Device) bool {
	if len(previous) != len(next) {
		return false
	}
	for id, device := range next {
		old, ok := previous[id]
		if !ok || old.Status != device.Status || old.Transport != device.Transport || old.ConnectKey != device.ConnectKey {
			return false
		}
	}
	return true
}

func (r *Registry) markStale(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready || now.Sub(r.lastSuccess) < r.staleAfter {
		return
	}
	for deviceID, device := range r.devices {
		if device.Status == model.TargetUnknown {
			continue
		}
		device.Status = model.TargetUnknown
		device.UpdatedAt = now
		r.devices[deviceID] = device
	}
}

func snapshot(devices map[string]model.Device) []model.Device {
	result := make([]model.Device, 0, len(devices))
	for _, device := range devices {
		result = append(result, device)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
