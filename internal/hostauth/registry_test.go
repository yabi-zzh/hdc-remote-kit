package hostauth

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistrySubmitDecideAndRevoke(t *testing.T) {
	registry := mustRegistry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan Decision, 1)
	go func() {
		decision, err := registry.Submit(ctx, PendingRequest{
			Hostname: "Alice-PC", Fingerprint: "abc123def4567890aaaa", Serial: "DEV1", SourceIP: "10.0.0.8",
		})
		if err != nil {
			t.Errorf("Submit() error = %v", err)
		}
		done <- decision
	}()
	waitPending(t, registry)
	if err := registry.Decide("abc123def4567890", DecisionAllowForever); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	select {
	case decision := <-done:
		if decision != DecisionAllowForever {
			t.Fatalf("decision = %q", decision)
		}
	case <-ctx.Done():
		t.Fatal("Submit() did not return after Decide()")
	}
	if !registry.Trusted("abc123def4567890aaaa") {
		t.Fatal("fingerprint was not persisted")
	}

	decision, err := registry.Submit(context.Background(), PendingRequest{Fingerprint: "abc123def4567890aaaa", Hostname: "Alice-PC"})
	if err != nil || decision != DecisionAllowForever {
		t.Fatalf("trusted Submit() = %q, %v", decision, err)
	}
	if err := registry.Revoke("abc123"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if registry.Trusted("abc123def4567890aaaa") {
		t.Fatal("fingerprint still trusted after revoke")
	}
	recent := registry.Recent()
	if len(recent) < 2 || recent[0].Action != "revoke" || recent[1].Action != string(DecisionAllowForever) {
		t.Fatalf("Recent() = %+v", recent)
	}
}

func TestRegistrySubmitExpires(t *testing.T) {
	registry := mustRegistry(t)
	registry.confirmTimeout = 20 * time.Millisecond
	decision, err := registry.Submit(context.Background(), PendingRequest{Fingerprint: "ffffeeee", Hostname: "Bob"})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if decision != DecisionExpired {
		t.Fatalf("decision = %q, want expired", decision)
	}
	if recent := registry.Recent(); len(recent) != 1 || recent[0].Action != string(DecisionExpired) {
		t.Fatalf("Recent() after expire = %+v", registry.Recent())
	}
	if len(registry.Pending()) != 0 {
		t.Fatalf("pending leftover = %+v", registry.Pending())
	}
}

func mustRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry
}

func waitPending(t *testing.T, registry *Registry) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(registry.Pending()) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending request did not appear")
}

func TestRegistryNotifyDedupesAndExpires(t *testing.T) {
	registry := mustRegistry(t)
	registry.confirmTimeout = 40 * time.Millisecond
	registry.Notify(Notice{
		Kind: NoticeClientVersionTooOld, Serial: "DEV1", SourceIP: "192.168.9.105",
		Version: "Ver: 2.0.0", Message: "upgrade",
	})
	registry.Notify(Notice{
		Kind: NoticeClientVersionTooOld, Serial: "DEV1", SourceIP: "192.168.9.105",
		Version: "Ver: 2.1.0", Message: "upgrade again",
	})
	notices := registry.Notices()
	if len(notices) != 1 {
		t.Fatalf("Notices() len = %d, want 1", len(notices))
	}
	if notices[0].Version != "Ver: 2.1.0" || notices[0].Message != "upgrade again" {
		t.Fatalf("deduped notice = %+v", notices[0])
	}
	time.Sleep(50 * time.Millisecond)
	if leftover := registry.Notices(); len(leftover) != 0 {
		t.Fatalf("expired Notices() = %+v", leftover)
	}
}

func TestRegistryPendingNewestFirst(t *testing.T) {
	registry := mustRegistry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	now := time.Now().UTC()
	go func() {
		_, _ = registry.Submit(ctx, PendingRequest{
			Hostname: "old", Fingerprint: "aaaa1111bbbb", CreatedAt: now.Add(-time.Minute),
		})
	}()
	go func() {
		_, _ = registry.Submit(ctx, PendingRequest{
			Hostname: "new", Fingerprint: "cccc2222dddd", CreatedAt: now,
		})
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(registry.Pending()) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	pending := registry.Pending()
	if len(pending) != 2 {
		t.Fatalf("Pending() len = %d, want 2", len(pending))
	}
	if pending[0].Hostname != "new" || pending[1].Hostname != "old" {
		t.Fatalf("order = %q then %q, want new then old", pending[0].Hostname, pending[1].Hostname)
	}
	_ = registry.Decide("aaaa1111bbbb", DecisionDeny)
	_ = registry.Decide("cccc2222dddd", DecisionDeny)
}

func TestRegistryDismissNoticeSuppressesRetry(t *testing.T) {
	registry := mustRegistry(t)
	registry.confirmTimeout = time.Second
	registry.Notify(Notice{
		Kind: NoticeClientVersionTooOld, Serial: "DEV1", SourceIP: "192.168.9.105",
		Version: "Ver: 2.0.0",
	})
	id := registry.Notices()[0].NoticeID
	if err := registry.DismissNotice(id); err != nil {
		t.Fatalf("DismissNotice() error = %v", err)
	}
	if leftover := registry.Notices(); len(leftover) != 0 {
		t.Fatalf("Notices() after dismiss = %+v", leftover)
	}
	registry.Notify(Notice{
		Kind: NoticeClientVersionTooOld, Serial: "DEV1", SourceIP: "192.168.9.105",
		Version: "Ver: 2.0.0",
	})
	if leftover := registry.Notices(); len(leftover) != 0 {
		t.Fatalf("suppressed Notify() = %+v", leftover)
	}
}

func TestKnownHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")
	if err := writeKnownHosts(path, []KnownHost{{Fingerprint: "aa", Hostname: "pc", CreatedAt: time.Unix(1, 0).UTC()}}); err != nil {
		t.Fatalf("writeKnownHosts() error = %v", err)
	}
	hosts, err := loadKnownHosts(path)
	if err != nil || len(hosts) != 1 || hosts[0].Fingerprint != "aa" {
		t.Fatalf("loadKnownHosts() = %+v, %v", hosts, err)
	}
}
