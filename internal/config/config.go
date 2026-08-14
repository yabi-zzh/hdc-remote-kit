// Package config 从环境变量加载并校验进程级配置，并套用偏安全的默认值。
// 运行参数通过 HDC_REMOTE_* 环境变量注入；本机确认台地址见 WebAddr。
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/policy"
)

const (
	// HostAuthConfirm 打开人工授权：未知公钥停在 Unauthorized，等本机确认台放行。
	HostAuthConfirm = "confirm"
	// HostAuthOff 关闭人工授权：未知公钥验签后直连，不写 known_hosts。
	HostAuthOff = "off"
)

// Config 是进程级配置。服务无控制面，启动后自动为在线 USB 设备开启转发，配置仅通过环境变量注入。
type Config struct {
	HDCAddr                  string
	ProxyBindHost            string
	PublicHost               string
	ProxyPortMin             int
	ProxyPortMax             int
	ServerNode               string
	StateDir                 string
	AllowedSourceCIDRs       []string
	LogLevel                 string // debug / info / warn / error，默认 info
	DevicePollInterval       time.Duration
	DeviceStaleAfter         time.Duration
	LeaseMaxTTL              time.Duration // 自动转发租约的保险 TTL，运行期持续刷新；服务异常停止刷新后租约到期自动关闭入口
	MaxConnections           int
	MaxChannelsPerConnection int
	HandshakeTimeout         time.Duration // AUTH_NONE→公钥提交及放行后验签的时限；待确认期间会清掉，改由 AuthConfirmTimeout 约束
	ShutdownTimeout          time.Duration // 优雅退出等待连接收敛的上限，超时则放弃等待直接退出
	HostConnectTimeout       time.Duration
	HostReadTimeout          time.Duration
	MaxHostPayloadBytes      int
	MaxDaemonFrameBytes      int
	MaxFileBytes             int64
	MaxTempBytes             int64
	FileTransferTimeout      time.Duration
	UnityStreamTimeout       time.Duration
	PolicyProfile            string        // 命令策略档位：studio-debug（默认）或 restricted（更严）
	ExtraDeniedExecutables   []string      // 在内置规则之上追加禁止的 shell 可执行名（只能加严）
	WebAddr                  string        // 本机确认台监听地址；空则不启动 Web，非回环启动失败
	AuthConfirmTimeout       time.Duration // 未知公钥停在 Unauthorized 等待本机放行的时限
	HostAuth                 string        // 默认 off：验签后直连；confirm：未知公钥等确认台
}

// Load 从环境变量读取配置并套用安全默认值（确认台默认本机回环、来源 CIDR 默认 loopback + RFC1918），最后经 validate 校验。
func Load() (Config, error) {
	proxyPortMin, err := envInt("HDC_REMOTE_PROXY_PORT_MIN", 50000)
	if err != nil {
		return Config{}, err
	}
	proxyPortMax, err := envInt("HDC_REMOTE_PROXY_PORT_MAX", 50500)
	if err != nil {
		return Config{}, err
	}
	maxConnections, err := envInt("HDC_REMOTE_MAX_CONNECTIONS", 2)
	if err != nil {
		return Config{}, err
	}
	maxChannels, err := envInt("HDC_REMOTE_MAX_CHANNELS_PER_CONNECTION", 64)
	if err != nil {
		return Config{}, err
	}
	maxHostPayload, err := envInt("HDC_REMOTE_MAX_HOST_PAYLOAD_BYTES", 1024*1024)
	if err != nil {
		return Config{}, err
	}
	maxDaemonFrame, err := envInt("HDC_REMOTE_MAX_DAEMON_FRAME_BYTES", 64*1024*1024)
	if err != nil {
		return Config{}, err
	}
	maxFileBytes, err := envInt64("HDC_REMOTE_MAX_FILE_BYTES", 2*1024*1024*1024)
	if err != nil {
		return Config{}, err
	}
	maxTempBytes, err := envInt64("HDC_REMOTE_MAX_TEMP_BYTES", 4*1024*1024*1024)
	if err != nil {
		return Config{}, err
	}
	durations, err := loadDurations()
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		HDCAddr:       envString("HDC_REMOTE_HDC_ADDR", "127.0.0.1:8710"),
		ProxyBindHost: envString("HDC_REMOTE_PROXY_BIND_HOST", "0.0.0.0"),
		PublicHost:    resolvePublicHost(os.Getenv("HDC_REMOTE_PUBLIC_HOST")),
		ProxyPortMin:  proxyPortMin,
		ProxyPortMax:  proxyPortMax,
		ServerNode:    envString("HDC_REMOTE_SERVER_NODE", "local"),
		StateDir:      envString("HDC_REMOTE_STATE_DIR", filepath.Join(".", "data")),
		// 默认放行 loopback + RFC1918 私网，与自动探测的局域网 public_host 对齐；公网仍需显式放宽。
		AllowedSourceCIDRs: envCSV("HDC_REMOTE_ALLOWED_SOURCE_CIDRS", []string{
			"127.0.0.1/32", "::1/128",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		}),
		LogLevel:                 strings.ToLower(envString("HDC_REMOTE_LOG_LEVEL", "info")),
		DevicePollInterval:       durations.devicePoll,
		DeviceStaleAfter:         durations.deviceStale,
		LeaseMaxTTL:              durations.leaseMaxTTL,
		MaxConnections:           maxConnections,
		MaxChannelsPerConnection: maxChannels,
		HandshakeTimeout:         durations.handshake,
		ShutdownTimeout:          durations.shutdown,
		HostConnectTimeout:       durations.hostConnect,
		HostReadTimeout:          durations.hostRead,
		MaxHostPayloadBytes:      maxHostPayload,
		MaxDaemonFrameBytes:      maxDaemonFrame,
		MaxFileBytes:             maxFileBytes,
		MaxTempBytes:             maxTempBytes,
		FileTransferTimeout:      durations.fileTransfer,
		UnityStreamTimeout:       durations.unityStream,
		PolicyProfile:            strings.ToLower(envString("HDC_REMOTE_POLICY_PROFILE", string(policy.ProfileStudioDebug))),
		ExtraDeniedExecutables:   envCSV("HDC_REMOTE_EXTRA_DENIED_EXECUTABLES", nil),
		WebAddr:                  envStringAllowEmpty("HDC_REMOTE_WEB_ADDR", "127.0.0.1:18080"),
		AuthConfirmTimeout:       durations.authConfirm,
		HostAuth:                 envString("HDC_REMOTE_HOST_AUTH", HostAuthOff),
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	cfg.HostAuth, _ = ParseHostAuth(cfg.HostAuth)
	return cfg, nil
}

// validate 强制安全与一致性约束：端口范围合法、超时/轮询/TTL/负载上限有序为正、CIDR 合法且非空。
func validate(cfg Config) error {
	if cfg.HDCAddr == "" || cfg.ServerNode == "" || cfg.PublicHost == "" {
		return fmt.Errorf("HDC address, server node and public host are required")
	}
	if cfg.ProxyPortMin <= 0 || cfg.ProxyPortMax < cfg.ProxyPortMin || cfg.ProxyPortMax > 65535 {
		return fmt.Errorf("invalid proxy port range: %d-%d", cfg.ProxyPortMin, cfg.ProxyPortMax)
	}
	if cfg.MaxConnections <= 0 || cfg.MaxChannelsPerConnection <= 0 {
		return fmt.Errorf("connection limits must be positive")
	}
	if cfg.HostConnectTimeout <= 0 || cfg.HostReadTimeout <= 0 || cfg.DevicePollInterval <= 0 ||
		cfg.DeviceStaleAfter < cfg.DevicePollInterval {
		return fmt.Errorf("timeouts and polling intervals are invalid")
	}
	if cfg.HandshakeTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return fmt.Errorf("handshake and shutdown timeouts must be positive")
	}
	if cfg.LeaseMaxTTL <= 0 {
		return fmt.Errorf("lease TTL must be positive")
	}
	if cfg.MaxHostPayloadBytes <= 0 || cfg.MaxDaemonFrameBytes <= 0 || cfg.MaxFileBytes <= 0 || cfg.MaxTempBytes < cfg.MaxFileBytes ||
		cfg.FileTransferTimeout <= 0 || cfg.UnityStreamTimeout <= 0 {
		return fmt.Errorf("payload, temporary storage and bridge timeouts are invalid")
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return fmt.Errorf("state directory is required")
	}
	for _, cidr := range cfg.AllowedSourceCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid allowed source CIDR %q: %w", cidr, err)
		}
	}
	if len(cfg.AllowedSourceCIDRs) == 0 {
		return fmt.Errorf("at least one allowed source CIDR is required")
	}
	if !policy.ValidProfile(cfg.PolicyProfile) {
		return fmt.Errorf("invalid policy profile %q", cfg.PolicyProfile)
	}
	if _, err := ParseLogLevel(cfg.LogLevel); err != nil {
		return err
	}
	if cfg.AuthConfirmTimeout <= 0 {
		return fmt.Errorf("auth confirm timeout must be positive")
	}
	if _, err := ParseHostAuth(cfg.HostAuth); err != nil {
		return err
	}
	if err := ValidateWebAddr(cfg.WebAddr); err != nil {
		return err
	}
	return nil
}

// ParseHostAuth 归一化主机授权模式。空值视为 off。
func ParseHostAuth(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case HostAuthConfirm, "on":
		return HostAuthConfirm, nil
	case "", HostAuthOff:
		return HostAuthOff, nil
	default:
		return "", fmt.Errorf("invalid host auth %q (want confirm|off)", value)
	}
}

// ValidateWebAddr 要求确认台只绑回环；空地址表示关闭确认台。
func ValidateWebAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid web addr %q: %w", addr, err)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("web addr %q is missing a port", addr)
	}
	if !IsLoopbackHost(host) {
		return fmt.Errorf("web addr %q must bind to loopback", addr)
	}
	return nil
}

// IsLoopbackHost 判定主机名是否为本机回环（含 localhost）。空主机（如 :18080）会绑到所有网卡，不是回环。
func IsLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// ParseLogLevel 将配置字符串解析为 slog.Level。
func ParseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want debug|info|warn|error)", value)
	}
}

// UnrestrictedSourceCIDRs 返回白名单中放行整个地址族的前缀（如 0.0.0.0/0、::/0）。
// 这类配置会把设备暴露给所有可达网络，必须在启动时显式告警。
func UnrestrictedSourceCIDRs(cidrs []string) []string {
	var unrestricted []string
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefix.Bits() == 0 {
			unrestricted = append(unrestricted, cidr)
		}
	}
	return unrestricted
}

// PublicHostNeedsSourceCIDRWarn 在展示地址非 loopback、但白名单仅含 loopback 时返回 true。
func PublicHostNeedsSourceCIDRWarn(publicHost string, cidrs []string) bool {
	host := strings.TrimSpace(publicHost)
	if host == "" || host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return false
	}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		if !addr.IsLoopback() {
			return false
		}
	}
	return len(cidrs) > 0
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// envStringAllowEmpty 在变量已设置时保留空值（用于关掉确认台）；未设置才用 fallback。
func envStringAllowEmpty(name, fallback string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	return strings.TrimSpace(value)
}

func envInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

func envInt64(name string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

// durationSettings 汇总所有时长配置，便于一次性解析并让错误指名具体环境变量。
type durationSettings struct {
	devicePoll   time.Duration
	deviceStale  time.Duration
	leaseMaxTTL  time.Duration
	handshake    time.Duration
	shutdown     time.Duration
	hostConnect  time.Duration
	hostRead     time.Duration
	fileTransfer time.Duration
	unityStream  time.Duration
	authConfirm  time.Duration
}

// durationSpec 把一个时长环境变量绑定到它的默认值与目标字段。
type durationSpec struct {
	name     string
	fallback time.Duration
	target   *time.Duration
}

func loadDurations() (durationSettings, error) {
	var settings durationSettings
	specs := []durationSpec{
		{"HDC_REMOTE_DEVICE_POLL_INTERVAL", 2 * time.Second, &settings.devicePoll},
		{"HDC_REMOTE_DEVICE_STALE_AFTER", 10 * time.Second, &settings.deviceStale},
		{"HDC_REMOTE_LEASE_MAX_TTL", 8 * time.Hour, &settings.leaseMaxTTL},
		{"HDC_REMOTE_HANDSHAKE_TIMEOUT", 10 * time.Second, &settings.handshake},
		{"HDC_REMOTE_SHUTDOWN_TIMEOUT", 10 * time.Second, &settings.shutdown},
		{"HDC_REMOTE_HOST_CONNECT_TIMEOUT", 3 * time.Second, &settings.hostConnect},
		{"HDC_REMOTE_HOST_READ_TIMEOUT", 5 * time.Second, &settings.hostRead},
		{"HDC_REMOTE_FILE_TRANSFER_TIMEOUT", 10 * time.Minute, &settings.fileTransfer},
		{"HDC_REMOTE_UNITY_STREAM_TIMEOUT", 30 * time.Minute, &settings.unityStream},
		{"HDC_REMOTE_AUTH_CONFIRM_TIMEOUT", 90 * time.Second, &settings.authConfirm},
	}
	for _, spec := range specs {
		value, err := envDuration(spec.name, spec.fallback)
		if err != nil {
			return durationSettings{}, err
		}
		*spec.target = value
	}
	return settings, nil
}

// envDuration 解析时长环境变量。解析失败必须报错并指名变量，
// 否则漏写单位（如 HOST_READ_TIMEOUT=5）会静默变成 0，最后只报一句笼统的校验失败。
func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

func envCSV(name string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return append([]string(nil), fallback...)
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		if normalized := strings.TrimSpace(item); normalized != "" {
			result = append(result, normalized)
		}
	}
	return result
}
