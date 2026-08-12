package remote

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

type fakeRegistry struct {
	devices map[string]model.Device
}

func (r *fakeRegistry) Devices() ([]model.Device, error) {
	result := make([]model.Device, 0, len(r.devices))
	for _, device := range r.devices {
		result = append(result, device)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (r *fakeRegistry) Find(identifier string) (model.Device, bool) {
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

func (r *fakeRegistry) ResolveOnlineUSB(deviceID string) (model.Device, error) {
	device, found := r.Find(deviceID)
	if !found || device.Transport != model.TransportUSB || device.Status != model.TargetOnline {
		return model.Device{}, ErrDeviceUnavailable
	}
	return device, nil
}

type memoryBindingStore struct {
	bindings []model.Binding
}

func (s *memoryBindingStore) Load() ([]model.Binding, error) {
	return append([]model.Binding(nil), s.bindings...), nil
}

func (s *memoryBindingStore) Save(bindings []model.Binding) error {
	s.bindings = append([]model.Binding(nil), bindings...)
	return nil
}

type fakeGateway struct {
	grants      []model.Grant
	updates     []model.Grant
	unbindCount int
}

func (g *fakeGateway) Bind(_ context.Context, grant model.Grant) error {
	g.grants = append(g.grants, grant)
	return nil
}

func (g *fakeGateway) UpdateGrant(grant model.Grant) error {
	g.updates = append(g.updates, grant)
	return nil
}

func (g *fakeGateway) Unbind(string) error {
	g.unbindCount++
	return nil
}

func (g *fakeGateway) Close() error { return nil }

// TestManagerRenewalPropagatesGrantToGateway 固化租约续期会同步到 listener 的 Grant 快照。
// 若只刷新 Manager 内的 Lease 而不同步 gateway，设备持续在线满 TTL 后
// admit 会依据过期快照拒绝所有新连接，且不会自行恢复。
func TestManagerRenewalPropagatesGrantToGateway(t *testing.T) {
	cfg := testConfig(t)
	registry := &fakeRegistry{devices: map[string]model.Device{
		"node:device": {ID: "node:device", ConnectKey: "device", Transport: model.TransportUSB, Status: model.TargetOnline},
	}}
	gateway := &fakeGateway{}
	manager, err := NewManager(registry, &memoryBindingStore{}, cfg, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	manager.SetGateway(gateway)
	now := time.Unix(100, 0)
	manager.now = func() time.Time { return now }

	request := model.AcquireRequest{DeviceIdentifier: "node:device", OwnerID: autoOwner, TTL: time.Hour}
	if _, err := manager.Acquire(context.Background(), request); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	firstExpiry := gateway.grants[0].ExpiresAt

	now = now.Add(30 * time.Minute)
	if _, err := manager.Acquire(context.Background(), request); err != nil {
		t.Fatalf("Acquire(renew) error = %v", err)
	}
	if len(gateway.grants) != 1 {
		t.Fatalf("renewal re-bound the listener: %d binds", len(gateway.grants))
	}
	if len(gateway.updates) != 1 {
		t.Fatalf("renewal did not update the listener grant: %d updates", len(gateway.updates))
	}
	renewed := gateway.updates[0]
	if !renewed.ExpiresAt.After(firstExpiry) {
		t.Fatalf("renewed grant expiry = %v, want after %v", renewed.ExpiresAt, firstExpiry)
	}
	if renewed.Binding.ID != gateway.grants[0].Binding.ID || renewed.LeaseID != gateway.grants[0].LeaseID {
		t.Fatalf("renewed grant identity drifted: %+v vs %+v", renewed, gateway.grants[0])
	}
	if len(renewed.AllowedSourcePrefixes) == 0 || renewed.MaxConnections <= 0 {
		t.Fatalf("renewed grant lost admission fields: %+v", renewed)
	}
}

func TestManagerKeepsStableBindingAcrossLeasesAndRestart(t *testing.T) {
	cfg := testConfig(t)
	registry := &fakeRegistry{devices: map[string]model.Device{
		"node:device": {ID: "node:device", ConnectKey: "device", Transport: model.TransportUSB, Status: model.TargetOnline},
	}}
	bindingStore := &memoryBindingStore{}
	gateway := &fakeGateway{}
	manager, err := NewManager(registry, bindingStore, cfg, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	manager.SetGateway(gateway)

	request := model.AcquireRequest{DeviceIdentifier: "node:device", OwnerID: "task-1"}
	first, err := manager.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(first) error = %v", err)
	}
	if first.LeaseID == "" || first.ProxyPort == 0 || first.ConnectCommand == "" {
		t.Fatalf("Acquire(first) view = %+v", first)
	}
	if err := manager.releaseLease(first.LeaseID, model.LeaseReleased); err != nil {
		t.Fatalf("releaseLease() error = %v", err)
	}
	second, err := manager.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(second) error = %v", err)
	}
	if second.ProxyPort != first.ProxyPort || second.LeaseID == first.LeaseID {
		t.Fatalf("binding was not stable: first=%+v second=%+v", first, second)
	}

	restarted, err := NewManager(registry, bindingStore, cfg, nil)
	if err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	if binding := restarted.bindingsByDevice["node:device"]; binding.Port != first.ProxyPort || binding.Status != model.BindingReserved {
		t.Fatalf("restored binding = %+v", binding)
	}
	if len(restarted.leasesByDevice) != 0 {
		t.Fatalf("active leases were restored: %+v", restarted.leasesByDevice)
	}
}

func TestManagerExpiresLeaseWithoutReleasingBinding(t *testing.T) {
	cfg := testConfig(t)
	registry := &fakeRegistry{devices: map[string]model.Device{
		"node:device": {ID: "node:device", ConnectKey: "device", Transport: model.TransportUSB, Status: model.TargetOnline},
	}}
	bindingStore := &memoryBindingStore{}
	gateway := &fakeGateway{}
	manager, err := NewManager(registry, bindingStore, cfg, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	manager.SetGateway(gateway)
	now := time.Unix(100, 0)
	manager.now = func() time.Time { return now }

	view, err := manager.Acquire(context.Background(), model.AcquireRequest{DeviceIdentifier: "node:device", TTL: time.Minute})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	now = now.Add(time.Minute)
	manager.reconcile(context.Background())
	if len(manager.leasesByDevice) != 0 || gateway.unbindCount != 1 {
		t.Fatalf("expired lease was not removed: leases=%d unbinds=%d", len(manager.leasesByDevice), gateway.unbindCount)
	}
	if binding := manager.bindingsByDevice["node:device"]; binding.Port != view.ProxyPort || binding.Status != model.BindingReserved {
		t.Fatalf("binding after expiry = %+v", binding)
	}
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return config.Config{
		ProxyBindHost: "127.0.0.1", PublicHost: "example.test",
		ProxyPortMin: port, ProxyPortMax: port,
		AllowedSourceCIDRs: []string{"127.0.0.1/32"},
		LeaseMaxTTL:        time.Hour,
		MaxConnections:     2,
	}
}
