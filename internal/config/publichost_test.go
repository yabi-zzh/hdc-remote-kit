package config

import (
	"net"
	"testing"
)

func TestResolvePublicHostUsesEnv(t *testing.T) {
	got := resolvePublicHost("  example.test  ")
	if got != "example.test" {
		t.Fatalf("resolvePublicHost() = %q, want example.test", got)
	}
}

func TestResolvePublicHostAutoDetects(t *testing.T) {
	got := resolvePublicHost("")
	if got == "" {
		t.Fatal("resolvePublicHost() returned empty host")
	}
	if ip := net.ParseIP(got); ip != nil && ip.To4() != nil && !isAdvertisableIPv4(ip) {
		t.Fatalf("auto-detected host %q is not advertisable", got)
	}
}

func TestIsAdvertisableIPv4RejectsFakeIP(t *testing.T) {
	if isAdvertisableIPv4(net.ParseIP("198.18.0.1")) {
		t.Fatal("198.18.0.1 should be rejected as Fake-IP range")
	}
	if !isAdvertisableIPv4(net.ParseIP("192.168.1.8")) {
		t.Fatal("192.168.1.8 should be advertisable")
	}
}

func TestLoadPublicHostEnvOverridesDetect(t *testing.T) {
	t.Setenv("HDC_REMOTE_PUBLIC_HOST", "pub.example.test")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.PublicHost != "pub.example.test" {
		t.Fatalf("PublicHost = %q, want pub.example.test", cfg.PublicHost)
	}
}

func TestLoadPublicHostAutoDetectWhenUnset(t *testing.T) {
	t.Setenv("HDC_REMOTE_PUBLIC_HOST", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.PublicHost == "" {
		t.Fatal("PublicHost should auto-detect when unset")
	}
}
