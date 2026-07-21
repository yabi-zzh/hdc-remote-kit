package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestFrameMatchesOfficialWireFixture(t *testing.T) {
	codec := NewCodec(1024)
	got := codec.EncodeFrame(1, CommandShellData, []byte("x"))
	want, err := hex.DecodeString("4857000001000900000001080110d10f1800200978")
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeFrame() = %x, want official fixture %x", got, want)
	}

	frame, err := codec.Decode(want)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if frame.ChannelID != 1 || frame.CommandFlag != CommandShellData || frame.CommandName != "ShellData" {
		t.Fatalf("unexpected frame metadata: %+v", frame)
	}
	if !bytes.Equal(frame.Payload, []byte("x")) {
		t.Fatalf("payload = %q, want x", frame.Payload)
	}
}

func TestFrameRejectsUnsupportedHeaderAndChecksum(t *testing.T) {
	codec := NewCodec(1024)

	unsupportedVersion := codec.EncodeFrame(1, CommandShellData, nil)
	unsupportedVersion[4] = 2
	if _, err := codec.Decode(unsupportedVersion); err == nil {
		t.Fatal("Decode() error = nil, want protocol version error")
	}

	unsupportedOptions := codec.EncodeFrame(1, CommandShellData, nil)
	unsupportedOptions[2] = 1
	if _, err := codec.Decode(unsupportedOptions); err == nil {
		t.Fatal("Decode() error = nil, want frame options error")
	}

	payload := []byte("abc")
	checksummed := encodeTestFrame(1, CommandShellData, payload, payloadChecksum(payload))
	if _, err := codec.Decode(checksummed); err != nil {
		t.Fatalf("Decode(checksummed) error = %v", err)
	}
	checksummed[len(checksummed)-1]++
	if _, err := codec.Decode(checksummed); err == nil {
		t.Fatal("Decode() error = nil, want checksum error")
	}
}

func TestDaemonFrameReadRejectsInvalidSize(t *testing.T) {
	codec := NewCodec(32)
	raw := codec.EncodeFrame(1, CommandShellData, make([]byte, 33))
	if _, err := codec.ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("ReadFrame() error = nil, want size error")
	}

	tooSmallCodec := NewCodec(DaemonHeaderBytes)
	if _, err := tooSmallCodec.ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("ReadFrame() error = nil, want maximum frame size error")
	}
}

func TestHandshakeUsesOfficialDaemonResponseSemantics(t *testing.T) {
	codec := NewCodec(2048)
	requestHandshake := SessionHandshake{
		Banner: "OHOS HDC", AuthType: HandshakeAuthNone, SessionID: 77,
		ConnectKey: "agent:50000", Version: "Ver: 3.2.0c-buildhash",
	}
	requestFrame, err := codec.Decode(codec.EncodeFrame(0, CommandKernelHandshake, encodeSessionHandshake(requestHandshake)))
	if err != nil {
		t.Fatalf("Decode(request) error = %v", err)
	}
	decodedRequest, err := codec.DecodeSessionHandshake(requestFrame.Payload)
	if err != nil {
		t.Fatalf("DecodeSessionHandshake(request) error = %v", err)
	}

	responseFrame, err := codec.Decode(codec.EncodeHandshakeOK(requestFrame, decodedRequest, "device-1"))
	if err != nil {
		t.Fatalf("Decode(response) error = %v", err)
	}
	response, err := codec.DecodeSessionHandshake(responseFrame.Payload)
	if err != nil {
		t.Fatalf("DecodeSessionHandshake(response) error = %v", err)
	}
	if response.Banner != "OHOS HDC" || response.AuthType != HandshakeAuthOK {
		t.Fatalf("unexpected response handshake = %+v", response)
	}
	if response.SessionID != 0 || response.ConnectKey != "" {
		t.Fatalf("response leaked host session identity = %+v", response)
	}
	if response.Version != requestHandshake.Version {
		t.Fatalf("response version = %q, want echoed %q", response.Version, requestHandshake.Version)
	}
	for _, feature := range [][]byte{[]byte("devname"), []byte("daemonauthstatus"), []byte("1200"), []byte("enable")} {
		if !bytes.Contains([]byte(response.Buffer), feature) {
			t.Fatalf("response handshake does not contain %q: %q", feature, response.Buffer)
		}
	}
}

func TestHandshakeUsesFallbackVersionForVersionlessHost(t *testing.T) {
	codec := NewCodec(1024)
	requestFrame := Frame{ChannelID: 0}
	responseFrame, err := codec.Decode(codec.EncodeHandshakeOK(requestFrame, SessionHandshake{}, "device-1"))
	if err != nil {
		t.Fatalf("Decode(response) error = %v", err)
	}
	response, err := codec.DecodeSessionHandshake(responseFrame.Payload)
	if err != nil {
		t.Fatalf("DecodeSessionHandshake(response) error = %v", err)
	}
	if response.Version != HandshakeFallbackVersion {
		t.Fatalf("response version = %q, want %q", response.Version, HandshakeFallbackVersion)
	}
}

func TestChannelCloseResponseDecrementsRemainingCount(t *testing.T) {
	codec := NewCodec(1024)
	if response := codec.EncodeChannelCloseResponse(7, []byte{0}); response != nil {
		t.Fatalf("zero-count close response = %x, want nil", response)
	}
	response, err := codec.Decode(codec.EncodeChannelCloseResponse(7, []byte{1}))
	if err != nil {
		t.Fatalf("Decode(close response) error = %v", err)
	}
	if response.CommandFlag != CommandKernelChannelClose || !bytes.Equal(response.Payload, []byte{0}) {
		t.Fatalf("unexpected close response = %+v", response)
	}
}

func TestCommandCatalogSeparatesOfficialAndLegacyEntries(t *testing.T) {
	officialDescriptor, ok := LookupCommand(CommandServiceStart)
	if !ok || officialDescriptor.Name != "ServiceStart" || officialDescriptor.Origin != CommandOriginOfficial {
		t.Fatalf("official command descriptor = %+v, found = %v", officialDescriptor, ok)
	}
	legacyDescriptor, ok := LookupCommand(CommandLegacyFileRecvInit)
	if !ok || legacyDescriptor.Origin != CommandOriginLegacy {
		t.Fatalf("legacy command descriptor = %+v, found = %v", legacyDescriptor, ok)
	}
	if family := CommandFamily(19); family != FamilyUnknown {
		t.Fatalf("CommandFamily(19) = %q, want unknown", family)
	}
}

func TestExtractShellCommand(t *testing.T) {
	codec := NewCodec(1024)
	frame, err := codec.Decode(codec.EncodeFrame(1, CommandUnityExecute, []byte("echo hello\x00")))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if command := ExtractShellCommand(frame); command != "echo hello" {
		t.Fatalf("ExtractShellCommand() = %q", command)
	}
}

func encodeTestFrame(channelID uint32, command Command, payload []byte, checksum uint8) []byte {
	protect := encodeProtect(channelID, command, checksum)
	header := make([]byte, DaemonHeaderBytes)
	header[0], header[1], header[4] = 'H', 'W', DaemonProtocolVersion
	header[5], header[6] = byte(len(protect)>>8), byte(len(protect))
	payloadSize := uint32(len(payload))
	header[7], header[8], header[9], header[10] =
		byte(payloadSize>>24), byte(payloadSize>>16), byte(payloadSize>>8), byte(payloadSize)
	return append(append(header, protect...), payload...)
}
