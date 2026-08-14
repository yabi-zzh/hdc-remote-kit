// Package hostauth 实现远程 hdc 公钥握手的本机侧：指纹、验签、known_hosts 与待确认请求。
package hostauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

const (
	// AuthRSAEncrypt 是旧版「私钥加密 / 公钥解密」挑战。
	AuthRSAEncrypt AuthType = 0
	// AuthRSA3072SHA512 是现行 RSA-PSS + SHA-512 签名。
	AuthRSA3072SHA512 AuthType = 1

	hostPubkeySeparator = '\x0c'
	maxHostnameBytes    = 256
	maxPubkeyBytes      = 8 * 1024
)

// AuthType 对应官方 AuthVerifyType。
type AuthType uint8

// HostIdentity 是握手里解析出的远程主机身份。
type HostIdentity struct {
	Hostname    string
	PublicKey   string
	Fingerprint string
}

// ParseHostIdentity 解析 AUTH_PUBLICKEY 负载：hostname + 0x0C + PEM 公钥。
func ParseHostIdentity(buffer string) (HostIdentity, error) {
	separator := strings.IndexByte(buffer, hostPubkeySeparator)
	if separator <= 0 || separator+1 >= len(buffer) {
		return HostIdentity{}, fmt.Errorf("HDC host public key payload is invalid")
	}
	hostname := strings.TrimSpace(buffer[:separator])
	publicKey := strings.TrimSpace(buffer[separator+1:])
	if hostname == "" || publicKey == "" {
		return HostIdentity{}, fmt.Errorf("HDC host public key payload is incomplete")
	}
	if len(hostname) > maxHostnameBytes || len(publicKey) > maxPubkeyBytes {
		return HostIdentity{}, fmt.Errorf("HDC host public key payload is too large")
	}
	for _, r := range hostname {
		if r < 32 || r > 126 {
			return HostIdentity{}, fmt.Errorf("HDC host name contains invalid characters")
		}
	}
	if _, err := parseRSAPublicKey(publicKey); err != nil {
		return HostIdentity{}, err
	}
	return HostIdentity{
		Hostname:    hostname,
		PublicKey:   publicKey,
		Fingerprint: Fingerprint(publicKey),
	}, nil
}

// Fingerprint 是公钥 PEM 的 SHA-256 十六进制（64 字符），不入日志完整 PEM。
func Fingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(sum[:])
}

// ShortFingerprint 给操作者看的短指纹（前 16 个十六进制字符）。
func ShortFingerprint(fingerprint string) string {
	fingerprint = strings.TrimSpace(fingerprint)
	if len(fingerprint) > 16 {
		return fingerprint[:16]
	}
	return fingerprint
}

// ParseClientAuthType 从 AUTH_NONE 的 TLV 读对端验签算法；解析失败视为旧版 RSA_ENCRYPT。
func ParseClientAuthType(buffer string) AuthType {
	fields, err := protocol.ParseHandshakeTLV(buffer)
	if err != nil {
		return AuthRSAEncrypt
	}
	if fields[protocol.HandshakeTLVAuthType] == protocol.HandshakeAuthTypeSHA512 {
		return AuthRSA3072SHA512
	}
	return AuthRSAEncrypt
}

// VerifyChallenge 校验客户端对挑战 token 的应答。
func VerifyChallenge(publicKey, token, signature string, authType AuthType) error {
	key, err := parseRSAPublicKey(publicKey)
	if err != nil {
		return err
	}
	raw, err := decodeChallengeSignature(signature)
	if err != nil {
		return err
	}
	switch authType {
	case AuthRSA3072SHA512:
		sum := sha512.Sum512([]byte(token))
		if err := rsa.VerifyPSS(key, crypto.SHA512, sum[:], raw, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("HDC signature verification failed")
		}
		return nil
	default:
		plain, err := rsaPublicDecryptPKCS1v15(key, raw)
		if err != nil || string(plain) != token {
			return fmt.Errorf("HDC signature verification failed")
		}
		return nil
	}
}

func parseRSAPublicKey(publicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("HDC host public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("HDC host public key is invalid")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("HDC host public key is not RSA")
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("HDC host public key is too weak")
	}
	return key, nil
}

func decodeChallengeSignature(signature string) ([]byte, error) {
	trimmed := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, signature)
	if trimmed == "" {
		return nil, fmt.Errorf("HDC signature is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("HDC signature is not base64")
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("HDC signature is empty")
	}
	return raw, nil
}

// rsaPublicDecryptPKCS1v15 实现旧版 AUTH：客户端 RSA_private_encrypt，本端公钥解密。
func rsaPublicDecryptPKCS1v15(pub *rsa.PublicKey, cipher []byte) ([]byte, error) {
	size := pub.Size()
	if len(cipher) == 0 || len(cipher) > size {
		return nil, fmt.Errorf("HDC encrypted token has invalid length")
	}
	c := new(big.Int).SetBytes(cipher)
	if c.Cmp(pub.N) >= 0 {
		return nil, fmt.Errorf("HDC encrypted token is out of range")
	}
	em := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N).FillBytes(make([]byte, size))
	if em[0] != 0x00 || em[1] != 0x01 {
		return nil, fmt.Errorf("HDC encrypted token padding is invalid")
	}
	index := 2
	for index < len(em) && em[index] == 0xff {
		index++
	}
	if index < 10 || index >= len(em) || em[index] != 0x00 {
		return nil, fmt.Errorf("HDC encrypted token padding is invalid")
	}
	return em[index+1:], nil
}
