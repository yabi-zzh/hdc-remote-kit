package device

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

type scannerResult struct {
	devices []model.Device
	err     error
}

type sequenceScanner struct {
	results []scannerResult
	index   int
}

func (s *sequenceScanner) ListTargets(context.Context) ([]model.Device, error) {
	result := s.results[s.index]
	if s.index < len(s.results)-1 {
		s.index++
	}
	return append([]model.Device(nil), result.devices...), result.err
}

func TestRegistryProjectsOfflineAndStaleStates(t *testing.T) {
	now := time.Unix(100, 0)
	scanner := &sequenceScanner{results: []scannerResult{
		{devices: []model.Device{{ID: "node:device", ConnectKey: "device", Transport: model.TransportUSB, Status: model.TargetOnline}}},
		{devices: nil},
		{err: errors.New("HDC unavailable")},
	}}
	registry := NewRegistry(scanner, time.Second, 5*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	registry.now = func() time.Time { return now }

	registry.refresh(context.Background())
	device, found := registry.Find("node:device")
	if !found || device.Status != model.TargetOnline {
		t.Fatalf("first scan device = %+v, found = %v", device, found)
	}

	now = now.Add(time.Second)
	registry.refresh(context.Background())
	device, _ = registry.Find("node:device")
	if device.Status != model.TargetOffline {
		t.Fatalf("missing device status = %s", device.Status)
	}

	now = now.Add(6 * time.Second)
	registry.refresh(context.Background())
	device, _ = registry.Find("node:device")
	if device.Status != model.TargetUnknown {
		t.Fatalf("stale device status = %s", device.Status)
	}
}

// TestRegistryEvictsLongOfflineDevices 确认持续离线的设备最终被移出快照，
// 且中途的扫描失败（markStale）不会把淘汰计时清零。
func TestRegistryEvictsLongOfflineDevices(t *testing.T) {
	now := time.Unix(100, 0)
	online := []model.Device{{ID: "node:device", ConnectKey: "device", Transport: model.TransportUSB, Status: model.TargetOnline}}
	scanner := &sequenceScanner{results: []scannerResult{
		{devices: online},
		{devices: nil},
	}}
	staleAfter := 5 * time.Second
	registry := NewRegistry(scanner, time.Second, staleAfter, slog.New(slog.NewTextHandler(io.Discard, nil)))
	registry.now = func() time.Time { return now }

	registry.refresh(context.Background())
	now = now.Add(time.Second)
	registry.refresh(context.Background())
	if _, found := registry.Find("node:device"); !found {
		t.Fatal("device disappeared immediately after going offline")
	}

	// 一次扫描失败会把所有设备标记为 UNKNOWN 并刷新 UpdatedAt；淘汰计时不应因此重置。
	scanner.results = append(scanner.results, scannerResult{err: errors.New("HDC unavailable")})
	scanner.index = len(scanner.results) - 1
	now = now.Add(staleAfter + time.Second)
	registry.refresh(context.Background())

	scanner.results = []scannerResult{{devices: nil}}
	scanner.index = 0
	now = now.Add(registry.retainOffline)
	registry.refresh(context.Background())
	if _, found := registry.Find("node:device"); found {
		t.Fatal("device still present after the offline retention window elapsed")
	}
}
