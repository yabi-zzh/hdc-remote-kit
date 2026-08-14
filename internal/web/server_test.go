package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/config"
	"github.com/yabi-zzh/hdc-remote-kit/internal/hostauth"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestConsoleAllowsPendingRequest(t *testing.T) {
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	done := make(chan hostauth.Decision, 1)
	go func() {
		decision, submitErr := hosts.Submit(context.Background(), hostauth.PendingRequest{
			Hostname: "Alice-PC", Fingerprint: "abcdef0123456789ffff", SourceIP: "10.0.0.3",
		})
		if submitErr != nil {
			t.Errorf("Submit() error = %v", submitErr)
		}
		done <- decision
	}()
	waitWebPending(t, hosts)

	server := startConsole(t, hosts, nil)
	defer server.Close(context.Background())

	body, _ := json.Marshal(decisionRequest{Fingerprint: "abcdef0123456789ffff"})
	response := doConsole(t, server, http.MethodPost, "/api/allow", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	select {
	case decision := <-done:
		if decision != hostauth.DecisionAllowForever {
			t.Fatalf("decision = %q", decision)
		}
	case <-time.After(time.Second):
		t.Fatal("pending submit did not complete")
	}
}

type stubSessions struct {
	kicked string
}

func (s *stubSessions) Sessions() []model.LiveSession {
	return []model.LiveSession{{SessionID: "sess-1", Hostname: "ubuntu"}}
}

func (s *stubSessions) Kick(sessionID string) error {
	s.kicked = sessionID
	return nil
}

func TestConsoleSnapshotIncludesVersionNotice(t *testing.T) {
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	hosts.Notify(hostauth.Notice{
		Kind: hostauth.NoticeClientVersionTooOld, Serial: "FMR1", SourceIP: "192.168.9.105",
		Version: "Ver: 2.0.0", Required: "Ver: 3.0.0b", Message: "upgrade hdc",
	})
	server := startConsole(t, hosts, nil)
	defer server.Close(context.Background())

	response := doConsole(t, server, http.MethodGet, "/api/snapshot", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var view snapshot
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if len(view.Notices) != 1 || view.Notices[0].Kind != hostauth.NoticeClientVersionTooOld {
		t.Fatalf("notices = %+v", view.Notices)
	}
	if view.Notices[0].SourceIP != "192.168.9.105" || view.Notices[0].Version != "Ver: 2.0.0" {
		t.Fatalf("notice = %+v", view.Notices[0])
	}
	if view.MinHdcVersion != protocol.HandshakeMinAuthVersion {
		t.Fatalf("min_hdc_version = %q, want %q", view.MinHdcVersion, protocol.HandshakeMinAuthVersion)
	}
	if view.HostAuth != config.HostAuthConfirm {
		t.Fatalf("host_auth = %q, want %q", view.HostAuth, config.HostAuthConfirm)
	}
}

func TestConsoleDismissesNotice(t *testing.T) {
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	hosts.Notify(hostauth.Notice{
		Kind: hostauth.NoticeClientVersionTooOld, Serial: "FMR1", SourceIP: "192.168.9.105",
		Version: "Ver: 2.0.0",
	})
	id := hosts.Notices()[0].NoticeID
	server := startConsole(t, hosts, nil)
	defer server.Close(context.Background())

	body, _ := json.Marshal(decisionRequest{NoticeID: id})
	response := doConsole(t, server, http.MethodPost, "/api/dismiss", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if leftover := hosts.Notices(); len(leftover) != 0 {
		t.Fatalf("Notices() after dismiss = %+v", leftover)
	}
}

func TestConsoleKicksLiveSession(t *testing.T) {
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	sessions := &stubSessions{}
	server := startConsole(t, hosts, sessions)
	defer server.Close(context.Background())

	body, _ := json.Marshal(decisionRequest{SessionID: "sess-1"})
	response := doConsole(t, server, http.MethodPost, "/api/kick", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if sessions.kicked != "sess-1" {
		t.Fatalf("kicked = %q", sessions.kicked)
	}
}

func TestStartRejectsNonLoopbackAddr(t *testing.T) {
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	server := New("0.0.0.0:18080", hosts, nil, nil, config.HostAuthConfirm, nil)
	if err := server.Start(); err == nil {
		_ = server.Close(context.Background())
		t.Fatal("Start() with non-loopback addr error = nil")
	}
}

func TestConsoleRejectsMissingTokenForeignHostAndOrigin(t *testing.T) {
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	server := startConsole(t, hosts, nil)
	defer server.Close(context.Background())
	base := "http://" + server.listener.Addr().String()

	plain, err := http.Get(base + "/api/snapshot")
	if err != nil {
		t.Fatalf("GET without token error = %v", err)
	}
	defer plain.Body.Close()
	if plain.StatusCode != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", plain.StatusCode)
	}

	hostReq, err := http.NewRequest(http.MethodGet, base+"/api/snapshot", nil)
	if err != nil {
		t.Fatalf("host request: %v", err)
	}
	hostReq.Host = "evil.example:18080"
	hostReq.Header.Set(consoleTokenHeader, server.token)
	hostResp, err := http.DefaultClient.Do(hostReq)
	if err != nil {
		t.Fatalf("GET with foreign host error = %v", err)
	}
	defer hostResp.Body.Close()
	if hostResp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign host status = %d, want 403", hostResp.StatusCode)
	}

	originReq, err := http.NewRequest(http.MethodPost, base+"/api/allow", bytes.NewReader([]byte(`{"request_id":"x"}`)))
	if err != nil {
		t.Fatalf("origin request: %v", err)
	}
	originReq.Header.Set("Content-Type", "application/json")
	originReq.Header.Set(consoleTokenHeader, server.token)
	originReq.Header.Set("Origin", "http://evil.example")
	originResp, err := http.DefaultClient.Do(originReq)
	if err != nil {
		t.Fatalf("POST with foreign origin error = %v", err)
	}
	defer originResp.Body.Close()
	if originResp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d, want 403", originResp.StatusCode)
	}
}

func startConsole(t *testing.T, hosts *hostauth.Registry, sessions SessionViewer) *Server {
	t.Helper()
	server := New("127.0.0.1:0", hosts, nil, sessions, config.HostAuthConfirm, nil)
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	return server
}

func doConsole(t *testing.T, server *Server, method, path string, body []byte) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+server.listener.Addr().String()+path, reader)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set(consoleTokenHeader, server.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, path, err)
	}
	return response
}

func waitWebPending(t *testing.T, hosts *hostauth.Registry) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(hosts.Pending()) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending request did not appear")
}
