package auth

import (
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token1, err1 := GenerateToken()
	if err1 != nil {
		t.Fatalf("Expected no error, got %v", err1)
	}

	if len(token1) != 64 { // hex of 32 bytes
		t.Errorf("Expected token length 64, got %d", len(token1))
	}

	token2, _ := GenerateToken()
	if token1 == token2 {
		t.Errorf("Expected tokens to be different, but they are identical")
	}
}
