// Package logging 提供面向 CLI 的可读文本日志 Handler。
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NewTextLogger 构造人类可读的文本日志器：本地时间 + 级别 + 消息 + 属性。
// 示例：2026-07-21 10:21:29 INFO forwarding ready serial=abc connect="hdc tconn 192.168.1.8:50000"
func NewTextLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(&textHandler{w: w, level: level})
}

type textHandler struct {
	mu     sync.Mutex
	w      io.Writer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

func (h *textHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *textHandler) Handle(_ context.Context, record slog.Record) error {
	var b strings.Builder
	b.Grow(128 + len(record.Message))
	ts := record.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	b.WriteString(ts.Local().Format("2006-01-02 15:04:05"))
	b.WriteByte(' ')
	b.WriteString(strings.ToUpper(record.Level.String()))
	b.WriteByte(' ')
	b.WriteString(record.Message)

	for _, attr := range h.attrs {
		b.WriteByte(' ')
		writeAttr(&b, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Equal(slog.Attr{}) {
			return true
		}
		if len(h.groups) > 0 {
			attr.Key = strings.Join(h.groups, ".") + "." + attr.Key
		}
		b.WriteByte(' ')
		writeAttr(&b, attr)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &textHandler{
		w:      h.w,
		level:  h.level,
		attrs:  append(append([]slog.Attr(nil), h.attrs...), prefixAttrs(h.groups, attrs)...),
		groups: append([]string(nil), h.groups...),
	}
}

func (h *textHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &textHandler{
		w:      h.w,
		level:  h.level,
		attrs:  append([]slog.Attr(nil), h.attrs...),
		groups: append(append([]string(nil), h.groups...), name),
	}
}

func prefixAttrs(groups []string, attrs []slog.Attr) []slog.Attr {
	if len(groups) == 0 {
		return append([]slog.Attr(nil), attrs...)
	}
	prefix := strings.Join(groups, ".") + "."
	out := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		out[i] = slog.Attr{Key: prefix + attr.Key, Value: attr.Value}
	}
	return out
}

func writeAttr(b *strings.Builder, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	b.WriteString(attr.Key)
	b.WriteByte('=')
	switch attr.Value.Kind() {
	case slog.KindString:
		writeQuoted(b, attr.Value.String())
	case slog.KindInt64:
		b.WriteString(strconv.FormatInt(attr.Value.Int64(), 10))
	case slog.KindUint64:
		b.WriteString(strconv.FormatUint(attr.Value.Uint64(), 10))
	case slog.KindFloat64:
		b.WriteString(strconv.FormatFloat(attr.Value.Float64(), 'g', -1, 64))
	case slog.KindBool:
		b.WriteString(strconv.FormatBool(attr.Value.Bool()))
	case slog.KindDuration:
		b.WriteString(attr.Value.Duration().String())
	case slog.KindTime:
		b.WriteString(attr.Value.Time().Local().Format("2006-01-02 15:04:05"))
	default:
		writeQuoted(b, fmt.Sprint(attr.Value.Any()))
	}
}

func writeQuoted(b *strings.Builder, s string) {
	if s == "" || strings.IndexFunc(s, needsQuote) >= 0 {
		b.WriteByte('"')
		b.WriteString(strings.ReplaceAll(s, `"`, `\"`))
		b.WriteByte('"')
		return
	}
	b.WriteString(s)
}

func needsQuote(r rune) bool {
	return r <= ' ' || r == '=' || r == '"'
}
