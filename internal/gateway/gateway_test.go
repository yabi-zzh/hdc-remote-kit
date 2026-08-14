package gateway

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/bridge"
	"github.com/yabi-zzh/hdc-remote-kit/internal/hostauth"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/policy"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestDaemonConnectionRequiresHandshake(t *testing.T) {
	codec := protocol.NewCodec(2048)
	frame, err := codec.Decode(codec.EncodeFrame(1, protocol.CommandShellInit, nil))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	connection := newTestDaemonConnection(t, codec)
	if err := connection.route(frame); err == nil {
		t.Fatal("route() error = nil, want handshake violation")
	} else if _, ok := err.(*daemonProtocolViolation); !ok {
		t.Fatalf("route() error type = %T, want *daemonProtocolViolation", err)
	}
}

func TestDaemonConnectionAllowsChannelCloseDuringHandshake(t *testing.T) {
	codec := protocol.NewCodec(16 * 1024)
	connection := newTestDaemonConnection(t, codec)
	none, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, SessionID: 27,
		ConnectKey: "127.0.0.1:1234", Version: "Ver: 3.2.0c-test",
		Buffer: protocol.AppendHandshakeTLV("", protocol.HandshakeTLVAuthType, protocol.HandshakeAuthTypeSHA512),
	}))
	if err != nil {
		t.Fatalf("Decode(none) error = %v", err)
	}
	if err := connection.route(none); err != nil {
		t.Fatalf("route(none) error = %v", err)
	}
	closeFrame, err := codec.Decode(codec.EncodeChannelClose(0))
	if err != nil {
		t.Fatalf("Decode(close) error = %v", err)
	}
	if err := connection.route(closeFrame); err != nil {
		t.Fatalf("route(ChannelClose) during handshake error = %v", err)
	}
	if connection.handshakeAccepted {
		t.Fatal("ChannelClose must not complete handshake")
	}
}

func TestDaemonConnectionRejectsOldClientVersion(t *testing.T) {
	codec := protocol.NewCodec(16 * 1024)
	connection := newTestDaemonConnection(t, codec)
	connection.sourceIP = "192.168.9.105"
	none, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, SessionID: 27,
		ConnectKey: "127.0.0.1:1234", Version: "Ver: 2.0.0",
	}))
	if err != nil {
		t.Fatalf("Decode(none) error = %v", err)
	}
	if err := connection.route(none); !errors.Is(err, errHostAuthRejected) {
		t.Fatalf("route(none) error = %v, want errHostAuthRejected", err)
	}
	if connection.authPhase != authPhaseStart {
		t.Fatal("old client must not advance auth phase")
	}
	notices := connection.hosts.Notices()
	if len(notices) != 1 || notices[0].Kind != hostauth.NoticeClientVersionTooOld {
		t.Fatalf("Notices() = %+v", notices)
	}
	if notices[0].Version != "Ver: 2.0.0" || notices[0].SourceIP != "192.168.9.105" {
		t.Fatalf("notice = %+v", notices[0])
	}
	if notices[0].Required != protocol.HandshakeMinAuthVersion {
		t.Fatalf("required = %q", notices[0].Required)
	}
	if connection.currentCloseReason() != "version_too_old" {
		t.Fatalf("closeReason = %q, want version_too_old", connection.currentCloseReason())
	}
}

func TestDaemonConnectionHandshakeRequiresPublicKeyAuth(t *testing.T) {
	codec := protocol.NewCodec(16 * 1024)
	connection := newTestDaemonConnection(t, codec)
	key, pemText := mustGatewayTestKey(t)
	identity, err := hostauth.ParseHostIdentity("Alice-PC\x0c" + pemText)
	if err != nil {
		t.Fatalf("ParseHostIdentity() error = %v", err)
	}
	if err := persistTrusted(t, connection.hosts, identity); err != nil {
		t.Fatalf("persistTrusted() error = %v", err)
	}

	none, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, SessionID: 27,
		ConnectKey: "127.0.0.1:1234", Version: "Ver: 3.2.0c-test",
		Buffer: protocol.AppendHandshakeTLV("", protocol.HandshakeTLVAuthType, protocol.HandshakeAuthTypeSHA512),
	}))
	if err != nil {
		t.Fatalf("Decode(none) error = %v", err)
	}
	if err := connection.route(none); err != nil {
		t.Fatalf("route(none) error = %v", err)
	}
	if connection.handshakeAccepted {
		t.Fatal("handshakeAccepted after AUTH_NONE")
	}
	challenge := mustReadHandshake(t, codec, connection)
	if challenge.AuthType != protocol.HandshakeAuthPublicKey {
		t.Fatalf("first reply authType = %d, want PUBLICKEY", challenge.AuthType)
	}

	pubkey, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthPublicKey, Version: "Ver: 3.2.0c-test",
		Buffer: "Alice-PC\x0c" + pemText,
	}))
	if err != nil {
		t.Fatalf("Decode(pubkey) error = %v", err)
	}
	if err := connection.route(pubkey); err != nil {
		t.Fatalf("route(pubkey) error = %v", err)
	}
	signChallenge := mustReadHandshake(t, codec, connection)
	if signChallenge.AuthType != protocol.HandshakeAuthSignature || signChallenge.Buffer == "" {
		t.Fatalf("signature challenge = %+v", signChallenge)
	}

	signature := mustSignGatewayPSS(t, key, signChallenge.Buffer)
	signed, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthSignature, Version: "Ver: 3.2.0c-test",
		Buffer: signature,
	}))
	if err != nil {
		t.Fatalf("Decode(signature) error = %v", err)
	}
	if err := connection.route(signed); err != nil {
		t.Fatalf("route(signature) error = %v", err)
	}
	if !connection.handshakeAccepted {
		t.Fatal("handshakeAccepted = false")
	}
	accepted := mustReadHandshake(t, codec, connection)
	if accepted.AuthType != protocol.HandshakeAuthOK {
		t.Fatalf("final authType = %d", accepted.AuthType)
	}
	if !bytes.Contains([]byte(accepted.Buffer), []byte(protocol.DaemonAuthSuccess)) {
		t.Fatalf("final buffer = %q", accepted.Buffer)
	}
	if err := connection.route(none); err == nil {
		t.Fatal("repeated handshake error = nil")
	}
}

func TestDaemonConnectionOffHostAuthSkipsPending(t *testing.T) {
	codec := protocol.NewCodec(16 * 1024)
	connection := newTestDaemonConnection(t, codec)
	connection.hostAuthOff = true
	recorder := &recordingAuditor{}
	connection.recorder = recorder
	_, pemText := mustGatewayTestKey(t)
	none, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, Version: "Ver: 3.2.0c-test",
		Buffer: protocol.AppendHandshakeTLV("", protocol.HandshakeTLVAuthType, protocol.HandshakeAuthTypeSHA512),
	}))
	if err != nil {
		t.Fatalf("Decode(none) error = %v", err)
	}
	if err := connection.route(none); err != nil {
		t.Fatalf("route(none) error = %v", err)
	}
	if mustReadHandshake(t, codec, connection).AuthType != protocol.HandshakeAuthPublicKey {
		t.Fatal("first reply must be PUBLICKEY")
	}
	pubkey, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthPublicKey, Version: "Ver: 3.2.0c-test",
		Buffer: "ubuntu\x0c" + pemText,
	}))
	if err != nil {
		t.Fatalf("Decode(pubkey) error = %v", err)
	}
	if err := connection.route(pubkey); err != nil {
		t.Fatalf("route(pubkey) error = %v", err)
	}
	if len(connection.hosts.Pending()) != 0 {
		t.Fatalf("pending = %+v, want none when host auth is off", connection.hosts.Pending())
	}
	if mustReadHandshake(t, codec, connection).AuthType != protocol.HandshakeAuthSignature {
		t.Fatal("host auth off must send signature challenge")
	}
	found := false
	for _, event := range recorder.events {
		if event.Reason == "host auth off" && event.Fingerprint != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("audit events = %+v, want host auth off with fingerprint", recorder.events)
	}
}

type recordingAuditor struct {
	events []model.Audit
}

func (r *recordingAuditor) Record(event model.Audit) {
	r.events = append(r.events, event)
}

func TestDaemonConnectionUnknownHostSendsUnauthorizedThenWaits(t *testing.T) {
	codec := protocol.NewCodec(16 * 1024)
	connection := newTestDaemonConnection(t, codec)
	_, pemText := mustGatewayTestKey(t)
	none, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, Version: "Ver: 3.2.0c-test",
		Buffer: protocol.AppendHandshakeTLV("", protocol.HandshakeTLVAuthType, protocol.HandshakeAuthTypeSHA512),
	}))
	if err != nil {
		t.Fatalf("Decode(none) error = %v", err)
	}
	if err := connection.route(none); err != nil {
		t.Fatalf("route(none) error = %v", err)
	}
	if mustReadHandshake(t, codec, connection).AuthType != protocol.HandshakeAuthPublicKey {
		t.Fatal("first reply must be PUBLICKEY")
	}

	pubkey, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthPublicKey, Version: "Ver: 3.2.0c-test",
		Buffer: "ubuntu\x0c" + pemText,
	}))
	if err != nil {
		t.Fatalf("Decode(pubkey) error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- connection.route(pubkey) }()
	waitPending(t, connection.hosts)
	unauth := mustReadHandshake(t, codec, connection)
	if unauth.AuthType != protocol.HandshakeAuthOK || !bytes.Contains([]byte(unauth.Buffer), []byte(protocol.DaemonAuthUnauthorized)) {
		t.Fatalf("pending reply = %+v, want AUTH_OK + UNAUTH", unauth)
	}
	if err := connection.hosts.Decide(connection.hosts.Pending()[0].RequestID, hostauth.DecisionAllowOnce); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("route(pubkey) after allow = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("allow did not finish handshake")
	}
	if mustReadHandshake(t, codec, connection).AuthType != protocol.HandshakeAuthSignature {
		t.Fatal("allow must send signature challenge, not AUTH_OK")
	}
	if connection.handshakeAccepted {
		t.Fatal("signature still required after allow")
	}
}

func TestDaemonConnectionDenyClosesWithoutCompletingHandshake(t *testing.T) {
	codec := protocol.NewCodec(16 * 1024)
	connection := newTestDaemonConnection(t, codec)
	_, pemText := mustGatewayTestKey(t)
	none, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthNone, Version: "Ver: 3.2.0c-test",
		Buffer: protocol.AppendHandshakeTLV("", protocol.HandshakeTLVAuthType, protocol.HandshakeAuthTypeSHA512),
	}))
	if err != nil {
		t.Fatalf("Decode(none) error = %v", err)
	}
	if err := connection.route(none); err != nil {
		t.Fatalf("route(none) error = %v", err)
	}
	_ = mustReadHandshake(t, codec, connection)

	pubkey, err := codec.Decode(codec.EncodeSessionHandshake(0, protocol.SessionHandshake{
		Banner: "OHOS HDC", AuthType: protocol.HandshakeAuthPublicKey, Version: "Ver: 3.2.0c-test",
		Buffer: "ubuntu\x0c" + pemText,
	}))
	if err != nil {
		t.Fatalf("Decode(pubkey) error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- connection.route(pubkey) }()
	waitPending(t, connection.hosts)
	if err := connection.hosts.Decide(connection.hosts.Pending()[0].RequestID, hostauth.DecisionDeny); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	select {
	case err := <-done:
		if err != errHostAuthRejected {
			t.Fatalf("route(pubkey) after deny = %v, want errHostAuthRejected", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deny did not finish handshake")
	}
	if connection.handshakeAccepted {
		t.Fatal("deny must not complete handshake")
	}
	if connection.currentCloseReason() != "deny" {
		t.Fatalf("closeReason = %q, want deny", connection.currentCloseReason())
	}
	denied := mustReadHandshake(t, codec, connection)
	if denied.AuthType != protocol.HandshakeAuthOK || !bytes.Contains([]byte(denied.Buffer), []byte(protocol.DaemonAuthUnauthorized)) {
		t.Fatalf("deny notice = %+v", denied)
	}
}

func waitPending(t *testing.T, registry *hostauth.Registry) {
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

func persistTrusted(t *testing.T, registry *hostauth.Registry, identity hostauth.HostIdentity) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), hostauth.PendingRequest{
			Hostname: identity.Hostname, Fingerprint: identity.Fingerprint,
		})
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(registry.Pending()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := registry.Decide(identity.Fingerprint, hostauth.DecisionAllowForever); err != nil {
		return err
	}
	return <-done
}

func mustReadHandshake(t *testing.T, codec *protocol.Codec, connection *daemonConnection) protocol.SessionHandshake {
	t.Helper()
	memory := connection.conn.(*memoryConn)
	raw, err := codec.ReadFrame(bytes.NewReader(memory.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	frame, err := codec.Decode(raw)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if frame.CommandFlag == protocol.CommandKernelChannelClose {
		memory.Next(len(raw))
		return mustReadHandshake(t, codec, connection)
	}
	if frame.CommandFlag != protocol.CommandKernelHandshake {
		t.Fatalf("command = %s, want handshake", frame.CommandName)
	}
	handshake, err := codec.DecodeSessionHandshake(frame.Payload)
	if err != nil {
		t.Fatalf("DecodeSessionHandshake() error = %v", err)
	}
	memory.Next(len(raw))
	return handshake
}

func mustGatewayTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func mustSignGatewayPSS(t *testing.T, key *rsa.PrivateKey, token string) string {
	t.Helper()
	sum := sha512.Sum512([]byte(token))
	raw, err := rsa.SignPSS(rand.Reader, key, crypto.SHA512, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatalf("SignPSS() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func newTestDaemonConnection(t *testing.T, codec *protocol.Codec) *daemonConnection {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hosts, err := hostauth.NewRegistry(t.TempDir(), time.Second, nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return &daemonConnection{
		ctx: ctx, cancel: cancel, hosts: hosts,
		conn:       &memoryConn{},
		binding:    model.Binding{DeviceID: "device-1"},
		codec:      codec,
		shells:     make(map[uint32]*shellSession),
		shellInput: make(map[uint32]*strings.Builder),
	}
}

func mustAppendShellInput(t *testing.T, connection *daemonConnection, channelID uint32, chunk string) string {
	t.Helper()
	guarded, ok := connection.appendShellInput(channelID, []byte(chunk))
	if !ok {
		t.Fatalf("appendShellInput(%q) rejected the input", chunk)
	}
	return guarded
}

func TestShellInputGuardCatchesCrossFrameCommand(t *testing.T) {
	connection := newTestDaemonConnection(t, protocol.NewCodec(4096))
	// 高危命令 "reboot" 被拆到多帧发送，单帧各自合法，累积后必须被识别。
	if decision := policy.InspectShellCommand(mustAppendShellInput(t, connection, 5, "reb")); !decision.Allowed {
		t.Fatal("partial chunk 'reb' should not be rejected on its own")
	}
	guarded := mustAppendShellInput(t, connection, 5, "oot\n")
	if decision := policy.InspectShellCommand(guarded); decision.Allowed {
		t.Fatalf("accumulated %q should be rejected", guarded)
	}
	// channel 关闭时窗口随之清理（生产在 stopShell/removeShell 内联 delete）；此处直接重置验证隔离。
	delete(connection.shellInput, 5)
	if decision := policy.InspectShellCommand(mustAppendShellInput(t, connection, 5, "ls\n")); !decision.Allowed {
		t.Fatal("benign command after clear should be allowed")
	}
}

// TestShellInputGuardDropsCompletedLines 确认已成行的输入不再留在窗口里：
// 否则每次按键都要重新解析整个历史，判定成本随会话长度二次增长。
func TestShellInputGuardDropsCompletedLines(t *testing.T) {
	connection := newTestDaemonConnection(t, protocol.NewCodec(4096))
	mustAppendShellInput(t, connection, 7, "echo hello\n")
	guarded := mustAppendShellInput(t, connection, 7, "ls")
	if guarded != "ls" {
		t.Fatalf("guard window = %q, want only the pending line %q", guarded, "ls")
	}
}

// TestShellInputGuardInspectsEntireChunk 确认护栏检查本帧送达设备的全部输入。
// 若只截取窗口尾部，「大段填充 + 高危命令」会把命令挤出检查范围而被放行。
func TestShellInputGuardInspectsEntireChunk(t *testing.T) {
	connection := newTestDaemonConnection(t, protocol.NewCodec(4096))
	padding := strings.Repeat("a", shellInputGuardLimit)
	guarded := mustAppendShellInput(t, connection, 7, "reboot\n"+padding)
	if decision := policy.InspectShellCommand(guarded); decision.Allowed {
		t.Fatal("high-risk command followed by padding should still be rejected")
	}
}

// TestShellInputGuardRejectsOversizedInput 超过判定上限时必须拒绝该帧，
// 而不是缩小检查范围后把未检查的内容转发给设备。
func TestShellInputGuardRejectsOversizedInput(t *testing.T) {
	connection := newTestDaemonConnection(t, protocol.NewCodec(4096))
	oversized := make([]byte, shellInputInspectLimit+1)
	for index := range oversized {
		oversized[index] = 'a'
	}
	if _, ok := connection.appendShellInput(7, oversized); ok {
		t.Fatal("oversized shell input should be rejected")
	}
}

// TestShellInputGuardBoundsPendingLine 一直没有换行的超长输入只保留尾部，避免残行无界增长。
func TestShellInputGuardBoundsPendingLine(t *testing.T) {
	connection := newTestDaemonConnection(t, protocol.NewCodec(4096))
	filler := strings.Repeat("a", shellInputGuardLimit)
	mustAppendShellInput(t, connection, 7, filler)
	guarded := mustAppendShellInput(t, connection, 7, "b")
	if guarded[len(guarded)-1] != 'b' {
		t.Fatal("guard window should retain the most recent byte")
	}
	if retained := connection.shellInput[7].Len(); retained != shellInputGuardLimit {
		t.Fatalf("pending line length = %d, want %d", retained, shellInputGuardLimit)
	}
}

type memoryConn struct {
	bytes.Buffer
}

func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return testAddress("local") }
func (c *memoryConn) RemoteAddr() net.Addr             { return testAddress("remote") }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddress string

func (a testAddress) Network() string { return "memory" }
func (a testAddress) String() string  { return string(a) }

type gatewayUnityTarget struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (t *gatewayUnityTarget) ReadPayload() ([]byte, error) {
	<-t.closed
	return nil, net.ErrClosed
}

func (t *gatewayUnityTarget) WritePayload([]byte) error { return nil }

func (t *gatewayUnityTarget) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func TestDaemonConnectionRoutesUnityFamily(t *testing.T) {
	codec := protocol.NewCodec(4096)
	connection := newTestDaemonConnection(t, codec)
	connection.handshakeAccepted = true
	opened := make(chan string, 1)
	target := &gatewayUnityTarget{closed: make(chan struct{})}
	connection.unityBridge = bridge.NewUnityBridge(context.Background(), codec, time.Second,
		func(_ context.Context, command string) (bridge.TargetChannel, error) {
			opened <- command
			return target, nil
		}, connection.write)
	defer connection.unityBridge.Close()

	frame, err := codec.Decode(codec.EncodeFrame(3, protocol.CommandUnityHilog, []byte("h")))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := connection.route(frame); err != nil {
		t.Fatalf("route(UnityHilog) error = %v", err)
	}
	select {
	case command := <-opened:
		if command != "hilog -h" {
			t.Fatalf("target command = %q, want %q", command, "hilog -h")
		}
	case <-time.After(time.Second):
		t.Fatal("Unity bridge did not open target channel")
	}
}

func TestGatewaySessionsExposeAuthedPeer(t *testing.T) {
	g := &Gateway{}
	g.trackSession(model.LiveSession{
		SessionID: "sess-1", Hostname: "ubuntu", Fingerprint: "d34f36ff",
		SourceIP: "192.168.9.116", Serial: "FMR0223824042727",
		ConnectedAt: time.Now().UTC(),
	}, nil)
	sessions := g.Sessions()
	if len(sessions) != 1 || sessions[0].Hostname != "ubuntu" || sessions[0].SourceIP != "192.168.9.116" {
		t.Fatalf("Sessions() = %+v", sessions)
	}
	g.dropSession("sess-1")
	if got := g.Sessions(); len(got) != 0 {
		t.Fatalf("Sessions() after drop = %+v", got)
	}
}

func TestClassifyReadEnd(t *testing.T) {
	if got := classifyReadEnd(io.EOF); got != "peer" {
		t.Fatalf("EOF = %q, want peer", got)
	}
	if got := classifyReadEnd(net.ErrClosed); got != "" {
		t.Fatalf("ErrClosed = %q, want empty so kicked/shutdown wins", got)
	}
	timeout := timeoutError{}
	if got := classifyReadEnd(timeout); got != "timeout" {
		t.Fatalf("timeout = %q, want timeout", got)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestGatewayKickClosesSession(t *testing.T) {
	g := &Gateway{}
	closed := false
	g.trackSession(model.LiveSession{
		SessionID: "sess-2", Hostname: "ubuntu", SourceIP: "192.168.9.116",
	}, func() { closed = true })
	if err := g.Kick("sess-2"); err != nil {
		t.Fatalf("Kick() error = %v", err)
	}
	if !closed {
		t.Fatal("Kick() did not close the session")
	}
	if got := g.Sessions(); len(got) != 0 {
		t.Fatalf("Sessions() after kick = %+v", got)
	}
	if err := g.Kick("sess-2"); err != ErrSessionNotFound {
		t.Fatalf("Kick() missing = %v, want ErrSessionNotFound", err)
	}
}
