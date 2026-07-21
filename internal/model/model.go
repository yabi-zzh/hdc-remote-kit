// Package model 定义领域模型与状态枚举：Device、Binding、Lease、Grant、RemoteAccessView、Audit。
// 仅承载数据、常量与状态定义，不含行为逻辑。
package model

import (
	"net/netip"
	"strings"
	"time"
)

// Transport 是设备与主 HDC server 之间的连接类型。
type Transport string

const (
	TransportUSB     Transport = "USB"
	TransportTCP     Transport = "TCP"
	TransportUnknown Transport = "UNKNOWN"
)

// TargetStatus 是设备在主 HDC server 上的在线状态。
type TargetStatus string

const (
	TargetOnline       TargetStatus = "ONLINE"
	TargetOffline      TargetStatus = "OFFLINE"
	TargetUnauthorized TargetStatus = "UNAUTHORIZED"
	TargetUnknown      TargetStatus = "UNKNOWN"
)

// Device 是主 HDC server 上一台 target 的事实快照，由 device.Registry 维护并对外投影。
type Device struct {
	ID         string       `json:"device_id"`
	ConnectKey string       `json:"connect_key"`
	Transport  Transport    `json:"transport"`
	Status     TargetStatus `json:"status"`
	Model      string       `json:"model,omitempty"`
	ServerNode string       `json:"server_node"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// DeviceSerial 从稳定 device ID（`serverNode:connectKey`）取出序列号/connectKey 段，便于日志关联。
func DeviceSerial(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	_, serial, ok := strings.Cut(deviceID, ":")
	if !ok || strings.TrimSpace(serial) == "" {
		return deviceID
	}
	return serial
}

// BindingStatus 表示设备代理端口绑定的生命周期状态。
// reserved → listening → frozen → released
type BindingStatus string

const (
	BindingReserved  BindingStatus = "RESERVED"
	BindingListening BindingStatus = "LISTENING"
	// FROZEN：设备 offline 或租约释放后保留端口，拒绝新连接，等待设备重新上线后恢复。
	BindingFrozen   BindingStatus = "FROZEN"
	BindingReleased BindingStatus = "RELEASED"
	BindingFailed   BindingStatus = "FAILED"
)

// Binding 是"设备 → 代理端口"的稳定映射，生命周期独立于租约。
// 设备 offline 后端口进入 FROZEN，重新 online 优先恢复原端口。
type Binding struct {
	ID         string        `json:"binding_id"`
	DeviceID   string        `json:"device_id"`
	PublicHost string        `json:"public_host"`
	Port       int           `json:"proxy_port"`
	Status     BindingStatus `json:"status"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

// LeaseStatus 表示远程接入租约的生命周期状态。
type LeaseStatus string

const (
	LeaseActive    LeaseStatus = "ACTIVE"
	LeaseReleasing LeaseStatus = "RELEASING"
	LeaseReleased  LeaseStatus = "RELEASED"
	LeaseExpired   LeaseStatus = "EXPIRED"
	LeaseRevoked   LeaseStatus = "REVOKED"
	LeaseFailed    LeaseStatus = "FAILED"
)

// Lease 控制"谁能从哪里、在什么时间内连接设备代理端口"。
// 同一设备同一时刻只允许一个 ACTIVE 租约；释放只关闭公网接入，不影响 Binding 和 USB 连接。
type Lease struct {
	ID                 string      `json:"lease_id"`
	BindingID          string      `json:"binding_id"`
	DeviceID           string      `json:"device_id"`
	OwnerID            string      `json:"owner_id,omitempty"`
	AllowedSourceCIDRs []string    `json:"allowed_source_cidrs,omitempty"`
	MaxConnections     int         `json:"max_connections"`
	ActiveConnections  int         `json:"active_connections"`
	PolicyProfile      string      `json:"policy_profile"`
	Status             LeaseStatus `json:"status"`
	ExpiresAt          time.Time   `json:"expires_at"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

// AcquireRequest 是远程访问用例的领域输入，不包含 HTTP 细节。
type AcquireRequest struct {
	DeviceIdentifier   string
	OwnerID            string
	AllowedSourceCIDRs []string
	TTL                time.Duration
	MaxConnections     int
	PolicyProfile      string
}

// Grant 是 Remote Service 提交给 Gateway 的不可变授权快照。
type Grant struct {
	LeaseID               string
	Binding               Binding
	DeviceID              string
	OwnerID               string
	AllowedSourcePrefixes []netip.Prefix
	MaxConnections        int
	ExpiresAt             time.Time
	PolicyProfile         string
}

// RemoteAccessStatus 是设备远程接入对外呈现的聚合状态。
type RemoteAccessStatus string

const (
	RemoteNotEnabled  RemoteAccessStatus = "NOT_ENABLED"
	RemoteConnectable RemoteAccessStatus = "CONNECTABLE"
	// CONNECTED：租约有效且当前存在活跃连接。
	RemoteConnected RemoteAccessStatus = "CONNECTED"
	RemoteReleasing RemoteAccessStatus = "RELEASING"
	RemoteReleased  RemoteAccessStatus = "RELEASED"
	RemoteFailed    RemoteAccessStatus = "FAILED"
)

// RemoteAccessView 是对外暴露的设备远程访问状态快照。
// Web 层只展示此结构，不感知底层 HDC 协议细节。
type RemoteAccessView struct {
	DeviceID           string             `json:"device_id"`
	DeviceName         string             `json:"device_name,omitempty"`
	USBStatus          TargetStatus       `json:"usb_status"`
	RemoteAccessStatus RemoteAccessStatus `json:"remote_access_status"`

	// 用户本机执行命令，例如 "hdc tconn your-domain.com:55001"
	ConnectCommand string `json:"connect_command,omitempty"`
	// 执行连接后用于验证的命令，固定为 "hdc list targets"
	VerifyCommand string `json:"verify_command,omitempty"`

	ProxyPort  int    `json:"proxy_port,omitempty"`
	PublicHost string `json:"public_host,omitempty"`

	LeaseID string `json:"lease_id,omitempty"`
	OwnerID string `json:"owner_id,omitempty"`

	AllowedSourceCIDRs []string   `json:"allowed_source_cidrs,omitempty"`
	MaxConnections     int        `json:"max_connections,omitempty"`
	ActiveConnections  int        `json:"active_connections,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`

	ErrorMessage              string `json:"error_message,omitempty"`
	LastRejectedCommandReason string `json:"last_rejected_command_reason,omitempty"`
}

// AuditDecision 表示命令策略决策结果。
type AuditDecision string

const (
	AuditAllowed  AuditDecision = "ALLOWED"
	AuditRejected AuditDecision = "REJECTED"
)

// Audit 记录每条通过网关的命令请求，用于安全审计和事后追溯。
type Audit struct {
	LeaseID           string        `json:"lease_id"`
	ConnectionID      string        `json:"connection_id"`
	DeviceID          string        `json:"device_id"`
	OwnerID           string        `json:"owner_id,omitempty"`
	SourceIP          string        `json:"source_ip"`
	CommandFlag       uint64        `json:"command_flag"`
	CommandName       string        `json:"command_name"`
	NormalizedCommand string        `json:"normalized_command,omitempty"`
	Decision          AuditDecision `json:"decision"`
	Reason            string        `json:"reason,omitempty"`
	CreatedAt         time.Time     `json:"created_at"`
}
