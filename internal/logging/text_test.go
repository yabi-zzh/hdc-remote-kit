package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestTextLoggerReadableFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)
	logger.Info("forwarding ready",
		"serial", "abc",
		"connect", "hdc tconn 192.168.1.8:50000",
	)

	out := buf.String()
	if strings.Contains(out, "time=") || strings.Contains(out, "level=") || strings.Contains(out, "msg=") {
		t.Fatalf("unexpected slog default keys in output: %q", out)
	}
	if !strings.Contains(out, " INFO forwarding ready ") {
		t.Fatalf("missing level/message layout: %q", out)
	}
	if !strings.Contains(out, `connect="hdc tconn 192.168.1.8:50000"`) || !strings.Contains(out, "serial=abc") {
		t.Fatalf("missing device/connect fields: %q", out)
	}
	prefix := out[:len("2006-01-02 15:04:05")]
	if _, err := time.ParseInLocation("2006-01-02 15:04:05", prefix, time.Local); err != nil {
		t.Fatalf("time prefix %q not local wall clock: %v", prefix, err)
	}
}
