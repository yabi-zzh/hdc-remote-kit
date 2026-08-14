package config

import (
	"log/slog"
	"testing"
)

func TestLoadRejectsInvalidNumbers(t *testing.T) {
	t.Setenv("HDC_REMOTE_PROXY_PORT_MIN", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with invalid port error = nil")
	}
}

func TestLoadAcceptsSecureDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.PublicHost == "" || len(cfg.AllowedSourceCIDRs) == 0 || cfg.LeaseMaxTTL <= 0 {
		t.Fatalf("Load() config = %+v", cfg)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.WebAddr != "127.0.0.1:18080" || cfg.AuthConfirmTimeout <= 0 {
		t.Fatalf("web/auth defaults = %+v", cfg)
	}
	if cfg.HostAuth != HostAuthOff {
		t.Fatalf("HostAuth = %q, want %q", cfg.HostAuth, HostAuthOff)
	}
}

func TestLoadAcceptsOffHostAuth(t *testing.T) {
	t.Setenv("HDC_REMOTE_HOST_AUTH", "OFF")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HostAuth != HostAuthOff {
		t.Fatalf("HostAuth = %q, want %q", cfg.HostAuth, HostAuthOff)
	}
}

func TestLoadAcceptsOnAsConfirmHostAuth(t *testing.T) {
	t.Setenv("HDC_REMOTE_HOST_AUTH", "on")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HostAuth != HostAuthConfirm {
		t.Fatalf("HostAuth = %q, want %q", cfg.HostAuth, HostAuthConfirm)
	}
}

func TestLoadRejectsInvalidHostAuth(t *testing.T) {
	t.Setenv("HDC_REMOTE_HOST_AUTH", "yes")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with invalid host auth error = nil")
	}
}

func TestLoadRejectsNonLoopbackWebAddr(t *testing.T) {
	t.Setenv("HDC_REMOTE_WEB_ADDR", "0.0.0.0:18080")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with non-loopback web addr error = nil")
	}
	t.Setenv("HDC_REMOTE_WEB_ADDR", ":18080")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with wildcard web addr error = nil")
	}
}

func TestLoadEmptyWebAddrDisablesConsole(t *testing.T) {
	t.Setenv("HDC_REMOTE_WEB_ADDR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.WebAddr != "" {
		t.Fatalf("WebAddr = %q, want empty", cfg.WebAddr)
	}
}

func TestValidateWebAddr(t *testing.T) {
	if err := ValidateWebAddr(""); err != nil {
		t.Fatalf("empty web addr error = %v", err)
	}
	if err := ValidateWebAddr("127.0.0.1:18080"); err != nil {
		t.Fatalf("loopback web addr error = %v", err)
	}
	if err := ValidateWebAddr("[::1]:18080"); err != nil {
		t.Fatalf("IPv6 loopback web addr error = %v", err)
	}
	if err := ValidateWebAddr("localhost:18080"); err != nil {
		t.Fatalf("localhost web addr error = %v", err)
	}
	if err := ValidateWebAddr("192.168.1.8:18080"); err == nil {
		t.Fatal("LAN web addr error = nil")
	}
}

func TestParseLogLevel(t *testing.T) {
	level, err := ParseLogLevel("debug")
	if err != nil || level != slog.LevelDebug {
		t.Fatalf("ParseLogLevel(debug) = %v, %v", level, err)
	}
	if _, err := ParseLogLevel("verbose"); err == nil {
		t.Fatal("ParseLogLevel(verbose) error = nil")
	}
}

func TestPublicHostNeedsSourceCIDRWarn(t *testing.T) {
	if !PublicHostNeedsSourceCIDRWarn("192.168.9.91", []string{"127.0.0.1/32", "::1/128"}) {
		t.Fatal("expected warn when LAN public host with loopback-only CIDRs")
	}
	if PublicHostNeedsSourceCIDRWarn("192.168.9.91", []string{"127.0.0.1/32", "192.168.0.0/16"}) {
		t.Fatal("did not expect warn when LAN CIDR already allowed")
	}
	if PublicHostNeedsSourceCIDRWarn("127.0.0.1", []string{"127.0.0.1/32"}) {
		t.Fatal("did not expect warn for loopback public host")
	}
}

func TestLoadRejectsInvalidProxyPortRange(t *testing.T) {
	t.Setenv("HDC_REMOTE_PROXY_PORT_MIN", "60000")
	t.Setenv("HDC_REMOTE_PROXY_PORT_MAX", "50000")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with inverted port range error = nil")
	}
}
