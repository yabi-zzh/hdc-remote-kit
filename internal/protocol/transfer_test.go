package protocol

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestTransferConfigRoundTrip(t *testing.T) {
	want := TransferConfig{
		FileSize: 42, ATime: 100, MTime: 200, Options: "-a -sync", Path: "/data/local/tmp/a.txt",
		OptionalName: "a.txt", UpdateIfNew: true, Compression: CompressionLZ4, HoldTimestamp: true,
		FunctionName: "file send", ClientCWD: "C:/work", Reserve1: "r1", Reserve2: "r2",
	}
	got, err := DecodeTransferConfig(EncodeTransferConfig(want))
	if err != nil {
		t.Fatalf("DecodeTransferConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("transfer config = %+v, want %+v", got, want)
	}
}

func TestTransferPayloadMatchesOfficialWireFixture(t *testing.T) {
	payload := TransferPayload{Index: 1, Compression: CompressionNone, CompressedSize: 3, UncompressedSize: 3}
	got := EncodeTransferPayload(payload)
	want, err := hex.DecodeString("0801100018032003")
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeTransferPayload() = %x, want official fixture %x", got, want)
	}
	decoded, err := DecodeTransferPayload(got)
	if err != nil {
		t.Fatalf("DecodeTransferPayload() error = %v", err)
	}
	if decoded != payload {
		t.Fatalf("transfer payload = %+v, want %+v", decoded, payload)
	}
}

func TestTransferDataUsesFixedPrefixAndValidatesSizes(t *testing.T) {
	header := TransferPayload{Index: 9, Compression: CompressionNone, CompressedSize: 3, UncompressedSize: 3}
	encoded, err := EncodeTransferData(header, []byte("abc"))
	if err != nil {
		t.Fatalf("EncodeTransferData() error = %v", err)
	}
	if len(encoded) != TransferPayloadPrefixBytes+3 {
		t.Fatalf("encoded transfer data length = %d", len(encoded))
	}
	if encoded[len(EncodeTransferPayload(header))] != 0 {
		t.Fatal("transfer payload prefix is not NUL padded")
	}

	decodedHeader, data, err := DecodeTransferData(encoded, 3)
	if err != nil {
		t.Fatalf("DecodeTransferData() error = %v", err)
	}
	if decodedHeader != header || !bytes.Equal(data, []byte("abc")) {
		t.Fatalf("decoded transfer data = %+v %q", decodedHeader, data)
	}

	if _, err := EncodeTransferData(header, []byte("ab")); err == nil {
		t.Fatal("EncodeTransferData() error = nil, want compressed size mismatch")
	}
	if _, _, err := DecodeTransferData(encoded[:TransferPayloadPrefixBytes-1], 3); err == nil {
		t.Fatal("DecodeTransferData() error = nil, want prefix length error")
	}
	if _, _, err := DecodeTransferData(encoded, 2); err == nil {
		t.Fatal("DecodeTransferData() error = nil, want uncompressed limit error")
	}

	invalidSize := append([]byte(nil), encoded...)
	invalidHeader := header
	invalidHeader.CompressedSize = 4
	copy(invalidSize, EncodeTransferPayload(invalidHeader))
	if _, _, err := DecodeTransferData(invalidSize, 4); err == nil {
		t.Fatal("DecodeTransferData() error = nil, want available data error")
	}
}

func TestTransferPayloadRejectsOutOfRangeNativeFields(t *testing.T) {
	payload := appendVarintField(nil, 2, uint64(^uint8(0))+1)
	if _, err := DecodeTransferPayload(payload); err == nil {
		t.Fatal("DecodeTransferPayload() error = nil, want compression range error")
	}

	payload = appendVarintField(nil, 3, uint64(^uint32(0))+1)
	if _, err := DecodeTransferPayload(payload); err == nil {
		t.Fatal("DecodeTransferPayload() error = nil, want uint32 range error")
	}
}
