// Package web 提供本机确认台：展示 pending / notice / 已验签会话，并调用 hostauth 裁决。
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/hostauth"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

const (
	consoleTokenHeader      = "X-HDC-Console-Token"
	consoleTokenPlaceholder = "__HDC_CONSOLE_TOKEN__"
	consoleTokenBytes       = 16
)

// DeviceViewer 提供设备远程接入快照，由 remote.Manager 实现。
type DeviceViewer interface {
	Views() []model.RemoteAccessView
}

// SessionViewer 提供已验签的远程连接，并支持本机踢出，由 gateway.Gateway 实现。
type SessionViewer interface {
	Sessions() []model.LiveSession
	Kick(sessionID string) error
}

// Server 是确认台 HTTP 服务；只监听回环，API 校验 Host/Origin 与启动时随机 token。
type Server struct {
	addr     string
	hostAuth string
	token    string
	hosts    *hostauth.Registry
	devices  DeviceViewer
	sessions SessionViewer
	logger   *slog.Logger
	http     *http.Server
	listener net.Listener
}

// New 构造确认台；addr 为空则不提供服务。
func New(addr string, hosts *hostauth.Registry, devices DeviceViewer, sessions SessionViewer, hostAuth string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if parsed, err := config.ParseHostAuth(hostAuth); err == nil {
		hostAuth = parsed
	} else {
		hostAuth = config.HostAuthOff
	}
	token, err := newConsoleToken()
	if err != nil {
		token = ""
	}
	return &Server{
		addr: strings.TrimSpace(addr), hostAuth: hostAuth, token: token,
		hosts: hosts, devices: devices, sessions: sessions, logger: logger,
	}
}

// Start 开始监听。调用方在后台跑 Serve。非回环地址直接失败。
func (s *Server) Start() error {
	if s.addr == "" {
		return nil
	}
	if err := config.ValidateWebAddr(s.addr); err != nil {
		return err
	}
	if s.token == "" {
		return fmt.Errorf("auth console token is unavailable")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/snapshot", s.handleSnapshot)
	mux.HandleFunc("/api/allow", s.handleAllow)
	mux.HandleFunc("/api/deny", s.handleDeny)
	mux.HandleFunc("/api/revoke", s.handleRevoke)
	mux.HandleFunc("/api/kick", s.handleKick)
	mux.HandleFunc("/api/dismiss", s.handleDismiss)
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		_ = listener.Close()
		return fmt.Errorf("auth console must bind to loopback, got %s", listener.Addr())
	}
	s.listener = listener
	s.http = &http.Server{Handler: s.protect(mux), ReadHeaderTimeout: 5 * time.Second}
	s.logger.Info("auth console listening", "url", "http://"+listener.Addr().String())
	go func() {
		if err := s.http.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Warn("auth console stopped", "error", err)
		}
	}()
	return nil
}

// Close 停止确认台。
func (s *Server) Close(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Cache-Control", "no-store")
		if !loopbackRemote(request.RemoteAddr) {
			http.Error(writer, "auth console is loopback only", http.StatusForbidden)
			return
		}
		if !loopbackHTTPHost(request.Host) {
			http.Error(writer, "invalid host header", http.StatusForbidden)
			return
		}
		if origin := strings.TrimSpace(request.Header.Get("Origin")); origin != "" && !loopbackOrigin(origin) {
			http.Error(writer, "invalid origin", http.StatusForbidden)
			return
		}
		if request.URL.Path != "/" && !s.tokenOK(request) {
			http.Error(writer, "missing console token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) tokenOK(request *http.Request) bool {
	got := strings.TrimSpace(request.Header.Get(consoleTokenHeader))
	if s.token == "" || got == "" || len(got) != len(s.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *Server) handleIndex(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := bytes.Replace(indexHTML, []byte(consoleTokenPlaceholder), []byte(s.token), 1)
	_, _ = writer.Write(page)
}

type snapshot struct {
	Pending       []hostauth.PendingRequest `json:"pending"`
	Notices       []hostauth.Notice         `json:"notices"`
	Keys          []hostauth.KnownHost      `json:"keys"`
	Devices       []model.RemoteAccessView  `json:"devices"`
	Sessions      []model.LiveSession       `json:"sessions"`
	MinHdcVersion string                    `json:"min_hdc_version"`
	HostAuth      string                    `json:"host_auth"`
}

func (s *Server) handleSnapshot(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	view := snapshot{
		Pending: s.hosts.Pending(), Notices: s.hosts.Notices(), Keys: s.hosts.Keys(),
		MinHdcVersion: protocol.HandshakeMinAuthVersion, HostAuth: s.hostAuth,
	}
	if s.devices != nil {
		view.Devices = s.devices.Views()
	}
	if s.sessions != nil {
		view.Sessions = s.sessions.Sessions()
	}
	writeJSON(writer, http.StatusOK, view)
}

type decisionRequest struct {
	RequestID   string `json:"request_id"`
	NoticeID    string `json:"notice_id"`
	Fingerprint string `json:"fingerprint"`
	SessionID   string `json:"session_id"`
	Once        bool   `json:"once"`
}

func (s *Server) handleAllow(writer http.ResponseWriter, request *http.Request) {
	s.handleDecision(writer, request, true)
}

func (s *Server) handleDeny(writer http.ResponseWriter, request *http.Request) {
	s.handleDecision(writer, request, false)
}

func (s *Server) handleDecision(writer http.ResponseWriter, request *http.Request, allow bool) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := decodeDecision(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	selector := firstNonEmpty(body.RequestID, body.Fingerprint)
	decision := hostauth.DecisionDeny
	if allow && body.Once {
		decision = hostauth.DecisionAllowOnce
	} else if allow {
		decision = hostauth.DecisionAllowForever
	}
	if err := s.hosts.Decide(selector, decision); err != nil {
		status := http.StatusBadRequest
		if err == hostauth.ErrNotFound {
			status = http.StatusNotFound
		}
		http.Error(writer, err.Error(), status)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "decision": string(decision)})
}

func (s *Server) handleDismiss(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := decodeDecision(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.hosts.DismissNotice(firstNonEmpty(body.NoticeID, body.RequestID)); err != nil {
		status := http.StatusBadRequest
		if err == hostauth.ErrNotFound {
			status = http.StatusNotFound
		}
		http.Error(writer, err.Error(), status)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleKick(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessions == nil {
		http.Error(writer, "session control is unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := decodeDecision(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.sessions.Kick(firstNonEmpty(body.SessionID, body.RequestID)); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		http.Error(writer, err.Error(), status)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRevoke(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := decodeDecision(request)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.hosts.Revoke(firstNonEmpty(body.Fingerprint, body.RequestID)); err != nil {
		status := http.StatusBadRequest
		if err == hostauth.ErrNotFound {
			status = http.StatusNotFound
		}
		http.Error(writer, err.Error(), status)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func decodeDecision(request *http.Request) (decisionRequest, error) {
	defer request.Body.Close()
	var body decisionRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, 8*1024)).Decode(&body); err != nil {
		return decisionRequest{}, err
	}
	return body, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func newConsoleToken() (string, error) {
	buffer := make([]byte, consoleTokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate auth console token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func loopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func loopbackHTTPHost(hostport string) bool {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return false
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	return config.IsLoopbackHost(host)
}

func loopbackOrigin(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return loopbackHTTPHost(parsed.Host)
}
