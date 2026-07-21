package hdc

import (
	"bytes"
	"testing"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

func TestParseTargets(t *testing.T) {
	raw := []byte("2UCUT23C19006484\t\tUSB\tOffline\tlocalhost\thdc\r\nFMR0223824042727\t\tUSB\tConnected\tMate\thdc\r\n")
	devices := parseTargets(raw, "node-a")
	if len(devices) != 2 {
		t.Fatalf("parseTargets() returned %d devices, want 2", len(devices))
	}
	if devices[0].ID != "node-a:2UCUT23C19006484" || devices[0].Transport != model.TransportUSB || devices[0].Status != model.TargetOffline {
		t.Fatalf("unexpected first device: %+v", devices[0])
	}
	if devices[1].Model != "Mate" || devices[1].Status != model.TargetOnline {
		t.Fatalf("unexpected second device: %+v", devices[1])
	}
}

func TestBuildClientHandshake(t *testing.T) {
	server := make([]byte, 44)
	copy(server, []byte("OHOS HDC"))
	copy(server[12:44], bytes.Repeat([]byte{'x'}, 32))
	client, err := buildClientHandshake(server, "device-key")
	if err != nil {
		t.Fatalf("buildClientHandshake() error = %v", err)
	}
	if string(client[:8]) != "OHOS HDC" {
		t.Fatalf("unexpected banner: %q", client[:8])
	}
	if string(client[12:]) != "device-key"+string(make([]byte, 22)) {
		t.Fatalf("unexpected connect key region: %q", client[12:])
	}
}
