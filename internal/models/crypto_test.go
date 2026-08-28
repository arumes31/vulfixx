package models

import (
	"strings"
	"testing"
)

func TestEncryptDecryptWebhook(t *testing.T) {
	// Test missing session key
	t.Setenv("SESSION_KEY", "")
	_, err := EncryptWebhook("secret")
	if err == nil || !strings.Contains(err.Error(), "missing SESSION_KEY") {
		t.Errorf("Expected 'missing SESSION_KEY' error, got %v", err)
	}

	// Set session key for remaining tests
	t.Setenv("SESSION_KEY", "super-secret-key-12345")

	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty string", ""},
		{"short string", "hello world"},
		{"long string", strings.Repeat("A", 1000)},
		{"special chars", "!@#$%^&*()_+{}[]|\\;:'\",./<>?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptWebhook(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptWebhook failed: %v", err)
			}

			if tt.plaintext == "" {
				if encrypted != "" {
					t.Errorf("Expected empty string, got %s", encrypted)
				}
			} else {
				if encrypted == "" {
					t.Error("Expected encrypted string, got empty string")
				}
				if encrypted == tt.plaintext {
					t.Error("Encrypted string is same as plaintext")
				}
			}

			decrypted, err := DecryptWebhook(encrypted)
			if err != nil {
				t.Fatalf("DecryptWebhook failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Expected decrypted string '%s', got '%s'", tt.plaintext, decrypted)
			}
		})
	}
}

func TestDecryptWebhookErrors(t *testing.T) {
	t.Setenv("SESSION_KEY", "super-secret-key-12345")

	t.Run("missing SESSION_KEY", func(t *testing.T) {
		t.Setenv("SESSION_KEY", "")
		_, err := DecryptWebhook("some-encrypted-data")
		if err == nil || !strings.Contains(err.Error(), "missing SESSION_KEY") {
			t.Errorf("Expected 'missing SESSION_KEY' error, got %v", err)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := DecryptWebhook("invalid-base64!")
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		// Valid base64, but decoded length is < nonceSize (12 for GCM)
		// Let's encode 5 bytes
		short := "YWFhYWE="
		_, err := DecryptWebhook(short)
		if err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
			t.Errorf("Expected 'ciphertext too short' error, got %v", err)
		}
	})

	t.Run("invalid ciphertext/authentication failed", func(t *testing.T) {
		// Encrypt valid data
		encrypted, _ := EncryptWebhook("secret data")

		// Change the key
		t.Setenv("SESSION_KEY", "different-secret-key")

		_, err := DecryptWebhook(encrypted)
		if err == nil {
			t.Error("Expected authentication error due to wrong key")
		}
	})
}
