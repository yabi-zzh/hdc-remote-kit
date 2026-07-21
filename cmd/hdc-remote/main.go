package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/audit"
	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/device"
	"github.com/yabi-zzh/hdc-remote-kit/internal/gateway"
	"github.com/yabi-zzh/hdc-remote-kit/internal/hdc"
	"github.com/yabi-zzh/hdc-remote-kit/internal/logging"
	"github.com/yabi-zzh/hdc-remote-kit/internal/remote"
	"github.com/yabi-zzh/hdc-remote-kit/internal/store"
)

// version 为构建版本号，发布时通过 -ldflags "-X main.version=..." 注入，默认 dev。
var version = "dev"

// main 完成进程装配与生命周期管理：加载配置 → 构建 host/registry/store/manager/audit/gateway 并互相接线 →
// 后台启动设备轮询与自动转发对账 → 等待退出信号 → 有序关闭（manager、audit）。
// 服务无控制面：启动后自动为每台在线 USB 设备开启转发，并在日志打印对应的 hdc tconn 连接命令。
func main() {
	showVersion := flag.Bool("version", false, "打印版本号并退出")
	logLevelFlag := flag.String("log-level", "", "日志级别：debug|info|warn|error（覆盖 HDC_REMOTE_LOG_LEVEL）")
	verbose := flag.Bool("v", false, "等价于 -log-level=debug")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	bootstrapLogger := logging.NewTextLogger(os.Stdout, slog.LevelInfo)
	cfg, err := config.Load()
	if err != nil {
		bootstrapLogger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	switch {
	case *verbose:
		cfg.LogLevel = "debug"
	case strings.TrimSpace(*logLevelFlag) != "":
		cfg.LogLevel = strings.TrimSpace(*logLevelFlag)
	}
	level, err := config.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		bootstrapLogger.Error("invalid log level", "error", err)
		os.Exit(1)
	}
	logger := logging.NewTextLogger(os.Stdout, level)

	host := hdc.NewHostClient(cfg, logger)
	registry := device.NewRegistry(host, cfg.DevicePollInterval, cfg.DeviceStaleAfter, logger)
	bindingStore := store.NewBindingStore(cfg.StateDir, cfg.ProxyPortMin, cfg.ProxyPortMax)
	manager, err := remote.NewManager(registry, bindingStore, cfg, logger)
	if err != nil {
		logger.Error("failed to restore remote access state", "error", err)
		os.Exit(1)
	}
	auditSink, err := audit.NewSink(cfg.StateDir, logger)
	if err != nil {
		logger.Error("failed to initialize audit sink", "error", err)
		os.Exit(1)
	}
	gatewayServer := gateway.New(cfg, manager, manager, host, auditSink, logger)
	manager.SetGateway(gatewayServer)

	runCtx, stopRuntime := context.WithCancel(context.Background())
	defer stopRuntime()
	go registry.Run(runCtx)
	go manager.Run(runCtx)
	logger.Info("HDC remote started", "version", version, "public_host", cfg.PublicHost)
	logger.Debug("HDC remote config",
		"hdc_addr", cfg.HDCAddr,
		"proxy_ports", fmt.Sprintf("%d-%d", cfg.ProxyPortMin, cfg.ProxyPortMax),
		"allowed_source_cidrs", strings.Join(cfg.AllowedSourceCIDRs, ","),
		"max_connections", cfg.MaxConnections,
		"profile", cfg.PolicyProfile)
	if config.PublicHostNeedsSourceCIDRWarn(cfg.PublicHost, cfg.AllowedSourceCIDRs) {
		logger.Warn("public_host is reachable over LAN but allowed_source_cidrs only allow loopback; remote tconn will be rejected",
			"public_host", cfg.PublicHost,
			"allowed_source_cidrs", strings.Join(cfg.AllowedSourceCIDRs, ","),
			"hint", "set HDC_REMOTE_ALLOWED_SOURCE_CIDRS to include client LAN, e.g. 192.168.0.0/16")
	}

	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, os.Interrupt, syscall.SIGTERM)
	receivedSignal := <-stopSignals
	logger.Info("HDC remote service shutdown requested", "signal", receivedSignal)

	stopRuntime()
	// 给后台对账循环一点时间退出后再收尾。
	time.Sleep(200 * time.Millisecond)
	if err := manager.Close(); err != nil {
		logger.Warn("HDC remote service cleanup failed", "error", err)
	}
	if err := auditSink.Close(); err != nil {
		logger.Warn("HDC remote audit shutdown failed", "error", err)
	}
	logger.Info("HDC remote service stopped")
}
