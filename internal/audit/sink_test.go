package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

func newTestSink(t *testing.T) (*Sink, string) {
	t.Helper()
	dir := t.TempDir()
	sink, err := NewSink(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	return sink, filepath.Join(dir, auditFileName)
}

func TestSinkAppendsEventsInOrderWithTimestamp(t *testing.T) {
	sink, path := newTestSink(t)
	for index := 0; index < 3; index++ {
		sink.Record(model.Audit{ConnectionID: string(rune('a' + index)), Decision: model.AuditAllowed})
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	lines := readJSONL(t, path)
	if len(lines) != 3 || lines[0].ConnectionID != "a" || lines[2].ConnectionID != "c" {
		t.Fatalf("persisted lines = %+v", lines)
	}
	for _, line := range lines {
		if line.CreatedAt.IsZero() {
			t.Fatalf("persisted audit has zero timestamp: %+v", line)
		}
	}
}

func TestSinkRecordAfterCloseIsDropped(t *testing.T) {
	sink, path := newTestSink(t)
	sink.Record(model.Audit{ConnectionID: "before"})
	if err := sink.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	sink.Record(model.Audit{ConnectionID: "after"})
	lines := readJSONL(t, path)
	if len(lines) != 1 || lines[0].ConnectionID != "before" {
		t.Fatalf("persisted lines after close = %+v", lines)
	}
}

func readJSONL(t *testing.T, path string) []model.Audit {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file error = %v", err)
	}
	defer file.Close()
	var result []model.Audit
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event model.Audit
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("unmarshal audit line error = %v", err)
		}
		result = append(result, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit file error = %v", err)
	}
	return result
}
