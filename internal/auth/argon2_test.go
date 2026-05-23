package auth

import (
	"testing"
)

func TestArgon2idHashingAndVerification(t *testing.T) {
	password := "superSecurePassword123"

	// Test successful hashing
	hash, err := hashPasswordArgon2id(password)
	if err != nil {
		t.Fatalf("failed to hash password with argon2id: %v", err)
	}

	if hash == "" {
		t.Fatalf("expected hash to be non-empty")
	}

	// Test successful verification
	matched, err := verifyPasswordArgon2id(hash, password)
	if err != nil {
		t.Fatalf("failed to verify argon2id password: %v", err)
	}
	if !matched {
		t.Errorf("expected password to match the hash")
	}

	// Test failed verification (wrong password)
	matched, err = verifyPasswordArgon2id(hash, "wrongPassword")
	if err != nil {
		t.Fatalf("unexpected error verifying password: %v", err)
	}
	if matched {
		t.Errorf("expected wrong password not to match")
	}

	// Test malformed hashes
	_, err = verifyPasswordArgon2id("invalid-hash", password)
	if err == nil {
		t.Errorf("expected error for malformed hash")
	}

	_, err = verifyPasswordArgon2id("$argon2id$v=19$m=65536,t=3,p=4$short", password)
	if err == nil {
		t.Errorf("expected error for incomplete hash parts")
	}

	_, err = verifyPasswordArgon2id("$argon2id$v=99$m=65536,t=3,p=4$salt$hash", password)
	if err == nil {
		t.Errorf("expected error for incompatible version")
	}

	_, err = verifyPasswordArgon2id("$argon2id$v=19$m=bad,t=3,p=4$salt$hash", password)
	if err == nil {
		t.Errorf("expected error for bad memory format")
	}

	_, err = verifyPasswordArgon2id("$argon2id$v=19$m=65536,t=3,p=4$invalid_base64_salt#$hash", password)
	if err == nil {
		t.Errorf("expected error for invalid base64 salt")
	}

	_, err = verifyPasswordArgon2id("$argon2id$v=19$m=65536,t=3,p=4$salt$invalid_base64_hash#", password)
	if err == nil {
		t.Errorf("expected error for invalid base64 hash")
	}

	_, err = verifyPasswordArgon2id("$argon2id$badversion$m=65536,t=3,p=4$c2FsdA$cGFzc3dvcmQ", password)
	if err == nil {
		t.Errorf("expected error for bad version format")
	}

	// 72 bytes base64 decoded is > 64 bytes
	_, err = verifyPasswordArgon2id("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ", password)
	if err == nil {
		t.Errorf("expected error for hash length > 64")
	}

	_, err = verifyPasswordArgon2id("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$", password)
	if err == nil {
		t.Errorf("expected error for hash length 0")
	}
}
