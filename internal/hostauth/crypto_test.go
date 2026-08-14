package hostauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestParseHostIdentityAndVerifyPSS(t *testing.T) {
	key, pemText := mustTestKey(t)
	identity, err := ParseHostIdentity("Alice-PC\x0c" + pemText)
	if err != nil {
		t.Fatalf("ParseHostIdentity() error = %v", err)
	}
	if identity.Hostname != "Alice-PC" || identity.Fingerprint == "" {
		t.Fatalf("identity = %+v", identity)
	}
	token := "challenge-token-20b!!"
	signature := mustSignPSS(t, key, token)
	if err := VerifyChallenge(identity.PublicKey, token, signature, AuthRSA3072SHA512); err != nil {
		t.Fatalf("VerifyChallenge() error = %v", err)
	}
	if err := VerifyChallenge(identity.PublicKey, "other", signature, AuthRSA3072SHA512); err == nil {
		t.Fatal("VerifyChallenge() accepted a mismatched token")
	}
}

func TestVerifyLegacyRSAEncrypt(t *testing.T) {
	key, pemText := mustTestKey(t)
	token := "legacy-token"
	cipher, err := rsaPrivateEncryptPKCS1v15(key, []byte(token))
	if err != nil {
		t.Fatalf("rsaPrivateEncryptPKCS1v15() error = %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(cipher)
	if err := VerifyChallenge(pemText, token, signature, AuthRSAEncrypt); err != nil {
		t.Fatalf("VerifyChallenge(legacy) error = %v", err)
	}
}

func TestParseClientAuthType(t *testing.T) {
	buffer := protocol.AppendHandshakeTLV("", protocol.HandshakeTLVAuthType, protocol.HandshakeAuthTypeSHA512)
	if got := ParseClientAuthType(buffer); got != AuthRSA3072SHA512 {
		t.Fatalf("ParseClientAuthType() = %d, want SHA512", got)
	}
	if got := ParseClientAuthType("not-tlv"); got != AuthRSAEncrypt {
		t.Fatalf("ParseClientAuthType(invalid) = %d, want encrypt", got)
	}
}

func TestParseHostIdentityRejectsGarbage(t *testing.T) {
	if _, err := ParseHostIdentity("only-host"); err == nil {
		t.Fatal("ParseHostIdentity() error = nil")
	}
	if _, err := ParseHostIdentity("host\x0cnot-a-pem"); err == nil {
		t.Fatal("ParseHostIdentity(pem) error = nil")
	}
}

func mustTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return key, pemText
}

func mustSignPSS(t *testing.T, key *rsa.PrivateKey, token string) string {
	t.Helper()
	sum := sha512.Sum512([]byte(token))
	raw, err := rsa.SignPSS(rand.Reader, key, crypto.SHA512, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatalf("SignPSS() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func rsaPrivateEncryptPKCS1v15(key *rsa.PrivateKey, message []byte) ([]byte, error) {
	size := key.PublicKey.Size()
	if len(message) > size-11 {
		return nil, rsa.ErrMessageTooLong
	}
	em := make([]byte, size)
	em[0] = 0x00
	em[1] = 0x01
	padEnd := size - len(message) - 1
	for i := 2; i < padEnd; i++ {
		em[i] = 0xff
	}
	em[padEnd] = 0x00
	copy(em[padEnd+1:], message)
	m := new(big.Int).SetBytes(em)
	return new(big.Int).Exp(m, key.D, key.N).FillBytes(make([]byte, size)), nil
}
