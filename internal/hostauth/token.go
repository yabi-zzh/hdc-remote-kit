package hostauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const challengeTokenBytes = 20

// NewChallengeToken 生成官方风格的 20 字节随机挑战（十六进制，40 字符）。
func NewChallengeToken() (string, error) {
	buffer := make([]byte, challengeTokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate HDC auth challenge: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
