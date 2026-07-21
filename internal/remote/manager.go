// Package remote 是远程接入编排核心：管理 Binding（持久）与 Lease（进程内）双状态机，
// 把在线 USB 设备事实投影为 Grant，驱动 gateway 自动开启与回收转发。
package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

// 远程接入编排的错误哨兵，调用方可用 errors.Is 判定具体失败原因。
var (
	ErrInvalidRequest     = errors.New("remote access request is invalid")
	ErrDeviceUnavailable  = errors.New("device is not an online USB target")
	ErrLeaseConflict      = errors.New("device already has an active lease")
	ErrGatewayUnavailable = errors.New("remote gateway is not initialized")
)

// DeviceRegistry 是设备事实来源契约，由 device.Registry 实现（只读快照，不触发扫描）。
type DeviceRegistry interface {
	Devices() ([]model.Device, error)
	Find(identifier string) (model.Device, bool)
	ResolveOnlineUSB(deviceID string) (model.Device, error)
}

// BindingStore 是稳定 Binding 持久化契约，由 store.BindingStore 实现。
type BindingStore interface {
	Load() ([]model.Binding, error)
	Save(bindings []model.Binding) error
}

// Gateway 是公网 daemon 入口契约，由 gateway.Gateway 实现；Manager 通过 Grant 驱动其启停 listener。
type Gateway interface {
	Bind(ctx context.Context, grant model.Grant) error
	Unbind(bindingID string) error
	Close() error
}

// autoOwner 是自动转发为在线设备创建租约时使用的 owner 标记。
const autoOwner = "auto"

// Manager 是远程接入编排核心：持有 Binding（持久）与 Lease（进程内）双状态机，
// 把设备事实投影为 Grant 交给 Gateway，并通过后台 reconcile 自动转发在线 USB 设备、冻结离线设备。
// 所有可变状态由 mu 串行保护；Binding 持久化，活跃 Lease 不持久化（重启后入口一律重新自动开启）。
type Manager struct {
	registry DeviceRegistry
	store    BindingStore
	cfg      config.Config
	ports    *portPool
	now      func() time.Time
	logger   *slog.Logger

	mu                 sync.Mutex
	gateway            Gateway
	bindingsByDevice   map[string]model.Binding
	bindingsByID       map[string]model.Binding
	leasesByDevice     map[string]model.Lease
	leasesByID         map[string]model.Lease
	inflightByDevice   map[string]struct{}
	lastRejectedReason map[string]string
}

// NewManager 构造编排器并从快照恢复稳定 Binding：恢复的端口重新占位、Binding 一律置为 RESERVED（不恢复 LISTENING）。
func NewManager(registry DeviceRegistry, bindingStore BindingStore, cfg config.Config, logger *slog.Logger) (*Manager, error) {
	bindings, err := bindingStore.Load()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	manager := &Manager{
		registry: registry, store: bindingStore, cfg: cfg, logger: logger,
		ports: newPortPool(cfg.ProxyBindHost, cfg.ProxyPortMin, cfg.ProxyPortMax), now: time.Now,
		bindingsByDevice: make(map[string]model.Binding), bindingsByID: make(map[string]model.Binding),
		leasesByDevice: make(map[string]model.Lease), leasesByID: make(map[string]model.Lease),
		inflightByDevice: make(map[string]struct{}), lastRejectedReason: make(map[string]string),
	}
	for _, binding := range bindings {
		if err := manager.ports.reserve(binding.Port); err != nil {
			return nil, fmt.Errorf("restore binding %q: %w", binding.ID, err)
		}
		binding.PublicHost = cfg.PublicHost
		binding.Status = model.BindingReserved
		manager.bindingsByDevice[binding.DeviceID] = binding
		manager.bindingsByID[binding.ID] = binding
	}
	return manager, nil
}

// SetGateway 注入 gateway（装配期一次性设置，与 Manager 互为 observer/resolver）。
func (m *Manager) SetGateway(gateway Gateway) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gateway = gateway
}

// Run 启动后台对账循环（每秒一次）：先 reconcile 收敛 Lease/Binding（保险 TTL 到期、离线冻结），
// 再 AutoExpose 自动转发在线 USB 设备并刷新其保险 TTL，直到 ctx 取消。
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reconcile(ctx)
			m.AutoExpose(ctx)
		}
	}
}

// Acquire 开启远程访问：校验入参 → 确认设备为在线 USB → 恢复或分配稳定 Binding → 创建 Lease/Grant → 启动 listener，
// 成功后提交 ACTIVE+LISTENING。同 owner 幂等返回原 Lease，不同 owner 冲突。任一步失败逆序清理，绝不返回未监听的端口。
func (m *Manager) Acquire(ctx context.Context, request model.AcquireRequest) (model.RemoteAccessView, error) {
	normalized, prefixes, err := m.normalizeAcquire(request)
	if err != nil {
		return failedView(normalized.DeviceIdentifier, err.Error()), err
	}
	device, err := m.registry.ResolveOnlineUSB(normalized.DeviceIdentifier)
	if err != nil {
		return failedView(normalized.DeviceIdentifier, "Device is not available."), fmt.Errorf("%w: %v", ErrDeviceUnavailable, err)
	}

	m.mu.Lock()
	if _, busy := m.inflightByDevice[device.ID]; busy {
		view := m.buildViewLocked(device, "Remote access operation is already in progress.")
		m.mu.Unlock()
		return view, ErrLeaseConflict
	}
	if lease, exists := m.leasesByDevice[device.ID]; exists && lease.Status == model.LeaseActive {
		if lease.OwnerID == normalized.OwnerID {
			// 同 owner 幂等：刷新保险 TTL（keepalive），使自动转发的租约在设备在线期间持续有效。
			lease.ExpiresAt = m.now().UTC().Add(normalized.TTL)
			lease.UpdatedAt = m.now().UTC()
			m.leasesByID[lease.ID] = lease
			m.leasesByDevice[device.ID] = lease
			view := m.buildViewLocked(device, "")
			m.mu.Unlock()
			return view, nil
		}
		view := m.buildViewLocked(device, "")
		m.mu.Unlock()
		view.ErrorMessage = "Device is already leased by another owner."
		view.RemoteAccessStatus = model.RemoteFailed
		return view, ErrLeaseConflict
	}
	gateway := m.gateway
	if gateway == nil {
		m.mu.Unlock()
		return failedView(device.ID, "Remote gateway is not initialized."), ErrGatewayUnavailable
	}
	m.inflightByDevice[device.ID] = struct{}{}
	binding, bindingExists := m.bindingsByDevice[device.ID]
	m.mu.Unlock()
	defer m.clearInflight(device.ID)

	if !bindingExists {
		binding, err = m.createBinding(device.ID)
		if err != nil {
			return failedView(device.ID, "Remote access port is not available."), err
		}
	}

	now := m.now().UTC()
	lease := model.Lease{
		ID: newID("lease"), BindingID: binding.ID, DeviceID: device.ID,
		OwnerID: normalized.OwnerID, AllowedSourceCIDRs: normalized.AllowedSourceCIDRs,
		MaxConnections: normalized.MaxConnections, PolicyProfile: normalized.PolicyProfile,
		Status: model.LeaseActive, ExpiresAt: now.Add(normalized.TTL), CreatedAt: now, UpdatedAt: now,
	}
	grant := model.Grant{
		LeaseID: lease.ID, Binding: binding, DeviceID: device.ID, OwnerID: lease.OwnerID,
		AllowedSourcePrefixes: prefixes, MaxConnections: lease.MaxConnections,
		ExpiresAt: lease.ExpiresAt, PolicyProfile: lease.PolicyProfile,
	}
	if err := gateway.Bind(ctx, grant); err != nil {
		return failedView(device.ID, "Remote access port is not available."), err
	}

	m.mu.Lock()
	binding.Status = model.BindingListening
	binding.UpdatedAt = m.now().UTC()
	m.bindingsByDevice[device.ID] = binding
	m.bindingsByID[binding.ID] = binding
	m.leasesByDevice[device.ID] = lease
	m.leasesByID[lease.ID] = lease
	view := m.buildViewLocked(device, "")
	m.mu.Unlock()
	return view, nil
}

// AutoExpose 为当前所有在线 USB 设备开启（或续期）转发：新设备首次暴露时打印 hdc tconn 连接命令。
// 幂等，每个 reconcile tick 调用一次即可保持在线设备持续可连；离线设备由 reconcile 冻结，不在此处理。
func (m *Manager) AutoExpose(ctx context.Context) {
	devices, err := m.registry.Devices()
	if err != nil {
		return
	}
	for _, device := range devices {
		if device.Transport != model.TransportUSB || device.Status != model.TargetOnline {
			continue
		}
		m.mu.Lock()
		lease, exposed := m.leasesByDevice[device.ID]
		alreadyActive := exposed && lease.Status == model.LeaseActive
		m.mu.Unlock()

		view, acquireErr := m.Acquire(ctx, model.AcquireRequest{
			DeviceIdentifier: device.ID,
			OwnerID:          autoOwner,
			TTL:              m.cfg.LeaseMaxTTL,
			PolicyProfile:    m.cfg.PolicyProfile,
		})
		if acquireErr != nil {
			m.logger.Warn("auto expose device failed", "serial", model.DeviceSerial(device.ID), "error", acquireErr)
			continue
		}
		if !alreadyActive {
			serial := device.ConnectKey
			if serial == "" {
				serial = model.DeviceSerial(device.ID)
			}
			m.logger.Info("forwarding ready", "serial", serial, "connect", view.ConnectCommand)
		}
	}
}

// ResolveOnlineConnectKey 供 gateway 在每次打开 target channel 时把 deviceID 解析为当前在线 USB 设备的 connectKey。
func (m *Manager) ResolveOnlineConnectKey(_ context.Context, deviceID string) (string, error) {
	device, err := m.registry.ResolveOnlineUSB(deviceID)
	if err != nil {
		return "", err
	}
	return device.ConnectKey, nil
}

// ConnectionOpened 是 gateway 连接事件回调：活跃连接数 +1。
func (m *Manager) ConnectionOpened(leaseID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, ok := m.leasesByID[leaseID]
	if !ok || lease.Status != model.LeaseActive {
		return
	}
	lease.ActiveConnections++
	lease.UpdatedAt = m.now().UTC()
	m.leasesByID[leaseID] = lease
	m.leasesByDevice[lease.DeviceID] = lease
}

// ConnectionClosed 是 gateway 连接事件回调：活跃连接数 -1。
func (m *Manager) ConnectionClosed(leaseID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, ok := m.leasesByID[leaseID]
	if !ok {
		return
	}
	if lease.ActiveConnections > 0 {
		lease.ActiveConnections--
	}
	lease.UpdatedAt = m.now().UTC()
	m.leasesByID[leaseID] = lease
	m.leasesByDevice[lease.DeviceID] = lease
}

// ConnectionRejected 记录该设备最近一次连接被拒原因，供 RemoteAccessView 展示（如超时、来源不允许、超并发）。
func (m *Manager) ConnectionRejected(leaseID, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if lease, ok := m.leasesByID[leaseID]; ok {
		m.lastRejectedReason[lease.DeviceID] = strings.TrimSpace(reason)
	}
}

// Close 关闭编排器：解绑所有活跃 listener、关闭 gateway 并持久化最终 Binding 快照。
func (m *Manager) Close() error {
	m.mu.Lock()
	gateway := m.gateway
	bindingIDs := make([]string, 0, len(m.leasesByDevice))
	for _, lease := range m.leasesByDevice {
		if binding, ok := m.bindingsByID[lease.BindingID]; ok {
			bindingIDs = append(bindingIDs, binding.ID)
		}
	}
	m.mu.Unlock()

	var closeErrors []error
	if gateway != nil {
		for _, bindingID := range bindingIDs {
			if err := gateway.Unbind(bindingID); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		if err := gateway.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	if err := m.saveBindings(); err != nil {
		closeErrors = append(closeErrors, err)
	}
	return errors.Join(closeErrors...)
}

func (m *Manager) createBinding(deviceID string) (model.Binding, error) {
	port, err := m.ports.allocate()
	if err != nil {
		return model.Binding{}, err
	}
	now := m.now().UTC()
	binding := model.Binding{
		ID: newID("binding"), DeviceID: deviceID, PublicHost: m.cfg.PublicHost, Port: port,
		Status: model.BindingReserved, CreatedAt: now, UpdatedAt: now,
	}
	m.mu.Lock()
	m.bindingsByDevice[deviceID] = binding
	m.bindingsByID[binding.ID] = binding
	m.mu.Unlock()
	if err := m.saveBindings(); err != nil {
		m.mu.Lock()
		delete(m.bindingsByDevice, deviceID)
		delete(m.bindingsByID, binding.ID)
		m.mu.Unlock()
		m.ports.release(port)
		return model.Binding{}, err
	}
	return binding, nil
}

// releaseLease 是释放的统一收敛点：Lease 转 RELEASING → Unbind listener → 删除 Lease 与相关计时 →
// 依设备是否在线把 Binding 置为 RESERVED/FROZEN → 持久化。Unbind 失败则 Lease 置 FAILED。
func (m *Manager) releaseLease(leaseID string, finalStatus model.LeaseStatus) error {
	m.mu.Lock()
	lease, ok := m.leasesByID[leaseID]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	lease.Status = model.LeaseReleasing
	lease.UpdatedAt = m.now().UTC()
	m.leasesByID[leaseID] = lease
	m.leasesByDevice[lease.DeviceID] = lease
	binding := m.bindingsByID[lease.BindingID]
	gateway := m.gateway
	m.mu.Unlock()

	if gateway != nil {
		if err := gateway.Unbind(binding.ID); err != nil {
			m.mu.Lock()
			lease.Status = model.LeaseFailed
			lease.UpdatedAt = m.now().UTC()
			m.leasesByID[leaseID] = lease
			m.leasesByDevice[lease.DeviceID] = lease
			m.mu.Unlock()
			return err
		}
	}

	device, online := m.registry.Find(lease.DeviceID)
	m.mu.Lock()
	delete(m.leasesByID, leaseID)
	delete(m.leasesByDevice, lease.DeviceID)
	if binding.ID != "" {
		if online && device.Status == model.TargetOnline && device.Transport == model.TransportUSB {
			binding.Status = model.BindingReserved
		} else {
			binding.Status = model.BindingFrozen
		}
		binding.UpdatedAt = m.now().UTC()
		m.bindingsByID[binding.ID] = binding
		m.bindingsByDevice[binding.DeviceID] = binding
	}
	m.mu.Unlock()
	if err := m.saveBindings(); err != nil {
		return err
	}
	// 与 AutoExpose 的 "device forwarding ready" 对称记录回收，reason 区分 TTL 到期与设备离线。
	m.logger.Info("forwarding stopped", "serial", model.DeviceSerial(lease.DeviceID), "reason", string(finalStatus))
	return nil
}

// reconcile 每个 tick：巡检 Lease（保险 TTL 到期→EXPIRED、设备离线/非 USB→REVOKED，命中即 releaseLease），
// 收敛无 Lease 的 Binding 状态，最后自动转发当前在线 USB 设备。
func (m *Manager) reconcile(ctx context.Context) {
	now := m.now().UTC()
	m.mu.Lock()
	leases := make([]model.Lease, 0, len(m.leasesByID))
	for _, lease := range m.leasesByID {
		leases = append(leases, lease)
	}
	m.mu.Unlock()

	for _, lease := range leases {
		finalStatus := model.LeaseStatus("")
		if !now.Before(lease.ExpiresAt) {
			finalStatus = model.LeaseExpired
		} else if device, ok := m.registry.Find(lease.DeviceID); !ok || device.Transport != model.TransportUSB || device.Status != model.TargetOnline {
			finalStatus = model.LeaseRevoked
		}
		if finalStatus != "" {
			_ = m.releaseLease(lease.ID, finalStatus)
		}
	}
	m.reconcileBindings(ctx)
}

func (m *Manager) reconcileBindings(context.Context) {
	m.mu.Lock()
	changed := false
	for deviceID, binding := range m.bindingsByDevice {
		if _, leased := m.leasesByDevice[deviceID]; leased {
			continue
		}
		device, found := m.registry.Find(deviceID)
		nextStatus := model.BindingFrozen
		if found && device.Transport == model.TransportUSB && device.Status == model.TargetOnline {
			nextStatus = model.BindingReserved
		}
		if binding.Status != nextStatus {
			binding.Status = nextStatus
			binding.UpdatedAt = m.now().UTC()
			m.bindingsByDevice[deviceID] = binding
			m.bindingsByID[binding.ID] = binding
			changed = true
			m.logger.Debug("binding status updated", "serial", model.DeviceSerial(deviceID), "status", string(nextStatus))
		}
	}
	m.mu.Unlock()
	if changed {
		_ = m.saveBindings()
	}
}

// normalizeAcquire 规范化并严格校验 acquire 入参：补默认 owner/profile/TTL/并发，套用范围上限，解析 CIDR 为 netip.Prefix。
func (m *Manager) normalizeAcquire(request model.AcquireRequest) (model.AcquireRequest, []netip.Prefix, error) {
	request.DeviceIdentifier = strings.TrimSpace(request.DeviceIdentifier)
	request.OwnerID = strings.TrimSpace(request.OwnerID)
	request.PolicyProfile = strings.TrimSpace(request.PolicyProfile)
	if request.DeviceIdentifier == "" {
		return request, nil, fmt.Errorf("%w: device identifier is required", ErrInvalidRequest)
	}
	if request.OwnerID == "" {
		request.OwnerID = "default"
	}
	if request.PolicyProfile == "" {
		request.PolicyProfile = "studio-debug"
	}
	if request.TTL <= 0 {
		request.TTL = m.cfg.LeaseMaxTTL
	}
	if request.TTL > m.cfg.LeaseMaxTTL {
		return request, nil, fmt.Errorf("%w: lease TTL is outside the configured range", ErrInvalidRequest)
	}
	if request.MaxConnections == 0 {
		request.MaxConnections = m.cfg.MaxConnections
	}
	if request.MaxConnections <= 0 || request.MaxConnections > m.cfg.MaxConnections {
		return request, nil, fmt.Errorf("%w: connection limit is outside the configured range", ErrInvalidRequest)
	}
	if len(request.AllowedSourceCIDRs) == 0 {
		request.AllowedSourceCIDRs = append([]string(nil), m.cfg.AllowedSourceCIDRs...)
	}
	prefixes := make([]netip.Prefix, 0, len(request.AllowedSourceCIDRs))
	for index, value := range request.AllowedSourceCIDRs {
		normalized := strings.TrimSpace(value)
		prefix, err := parsePrefix(normalized)
		if err != nil {
			return request, nil, fmt.Errorf("%w: invalid source CIDR %q", ErrInvalidRequest, value)
		}
		request.AllowedSourceCIDRs[index] = prefix.String()
		prefixes = append(prefixes, prefix)
	}
	return request, prefixes, nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}

// buildViewLocked 把设备事实 + Binding + Lease 投影为对外的 RemoteAccessView（含 connect/verify 命令、状态、连接计数）。
// 调用方必须持有 m.mu。
func (m *Manager) buildViewLocked(device model.Device, message string) model.RemoteAccessView {
	binding := m.bindingsByDevice[device.ID]
	lease := m.leasesByDevice[device.ID]
	view := model.RemoteAccessView{
		DeviceID: device.ID, DeviceName: device.Model, USBStatus: device.Status,
		RemoteAccessStatus: model.RemoteNotEnabled, ErrorMessage: message,
		PublicHost: binding.PublicHost, ProxyPort: binding.Port,
		LastRejectedCommandReason: m.lastRejectedReason[device.ID],
	}
	if view.DeviceName == "" {
		view.DeviceName = device.ConnectKey
	}
	if lease.ID == "" {
		return view
	}
	view.LeaseID = lease.ID
	view.OwnerID = lease.OwnerID
	view.AllowedSourceCIDRs = append([]string(nil), lease.AllowedSourceCIDRs...)
	view.MaxConnections = lease.MaxConnections
	view.ActiveConnections = lease.ActiveConnections
	expiresAt := lease.ExpiresAt
	view.ExpiresAt = &expiresAt
	view.ConnectCommand = fmt.Sprintf("hdc tconn %s:%d", binding.PublicHost, binding.Port)
	view.VerifyCommand = "hdc list targets"
	switch lease.Status {
	case model.LeaseActive:
		if lease.ActiveConnections > 0 {
			view.RemoteAccessStatus = model.RemoteConnected
		} else {
			view.RemoteAccessStatus = model.RemoteConnectable
		}
	case model.LeaseReleasing:
		view.RemoteAccessStatus = model.RemoteReleasing
	case model.LeaseFailed:
		view.RemoteAccessStatus = model.RemoteFailed
	}
	if message != "" {
		view.RemoteAccessStatus = model.RemoteFailed
	}
	return view
}

func failedView(deviceID, message string) model.RemoteAccessView {
	return model.RemoteAccessView{
		DeviceID: deviceID, USBStatus: model.TargetUnknown,
		RemoteAccessStatus: model.RemoteFailed, ErrorMessage: message,
	}
}

func (m *Manager) clearInflight(deviceID string) {
	m.mu.Lock()
	delete(m.inflightByDevice, deviceID)
	m.mu.Unlock()
}

func (m *Manager) saveBindings() error {
	m.mu.Lock()
	bindings := make([]model.Binding, 0, len(m.bindingsByDevice))
	for _, binding := range m.bindingsByDevice {
		bindings = append(bindings, binding)
	}
	m.mu.Unlock()
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].DeviceID < bindings[j].DeviceID })
	return m.store.Save(bindings)
}

func newID(prefix string) string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
