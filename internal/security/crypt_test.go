package security

import (
	"testing"
)

func TestEncryptionDecryption(t *testing.T) {
	plainText := "sentry-dsn-super-secret-key-123456"

	t.Run("EncryptAndDecrypt", func(t *testing.T) {
		cipherText, err := Encrypt(plainText)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		if cipherText == plainText {
			t.Errorf("encrypted text should be different from plaintext")
		}

		decryptedText, err := Decrypt(cipherText)
		if err != nil {
			t.Fatalf("failed to decrypt: %v", err)
		}

		if decryptedText != plainText {
			t.Errorf("expected decrypted text %q, got %q", plainText, decryptedText)
		}
	})

	t.Run("EmptyPlaintext", func(t *testing.T) {
		_, err := Encrypt("")
		if err != ErrEmptyPlainText {
			t.Errorf("expected ErrEmptyPlainText, got %v", err)
		}
	})

	t.Run("EmptyCiphertext", func(t *testing.T) {
		_, err := Decrypt("")
		if err != ErrEmptyCipherText {
			t.Errorf("expected ErrEmptyCipherText, got %v", err)
		}
	})

	t.Run("InvalidCiphertext", func(t *testing.T) {
		_, err := Decrypt("invalid-base-64!")
		if err == nil {
			t.Errorf("expected decryption error, got nil")
		}
	})
}
