package hostauth

import "testing"

func TestNewChallengeTokenLength(t *testing.T) {
	token, err := NewChallengeToken()
	if err != nil {
		t.Fatalf("NewChallengeToken() error = %v", err)
	}
	if len(token) != challengeTokenBytes*2 {
		t.Fatalf("token length = %d, want %d", len(token), challengeTokenBytes*2)
	}
}
