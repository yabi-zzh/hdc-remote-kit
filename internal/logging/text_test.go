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

// TestTextLoggerEscapesControlCharacters 防止日志注入：属性值里的换行必须被转义，
// 否则对端可影响的字符串（设备名、透传的错误文本）能伪造出一条以假乱真的日志行。
func TestTextLoggerEscapesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)
	logger.Info("device seen", "name", "a\n2026-01-01 00:00:00 INFO forged entry", "path", `C:\tmp\`)

	out := buf.String()
	if lines := strings.Count(strings.TrimRight(out, "\n"), "\n"); lines != 0 {
		t.Fatalf("attribute value broke the record into %d extra lines: %q", lines, out)
	}
	if !strings.Contains(out, `\n`) {
		t.Fatalf("newline was not escaped: %q", out)
	}
	if !strings.Contains(out, `\\`) {
		t.Fatalf("backslash was not escaped: %q", out)
	}
}
