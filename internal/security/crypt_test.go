package security

import (
	"testing"
)

func TestEncryptionDecryption(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "vulfixx-default-dev-secret-key-32bytes")
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

	t.Run("ShortCiphertext", func(t *testing.T) {
		// Base64 encode something shorter than 12 bytes nonce
		shortEncoded := "c2hvcnQ=" // "short" in base64
		_, err := Decrypt(shortEncoded)
		if err != ErrDecryption {
			t.Errorf("expected ErrDecryption for short ciphertext, got %v", err)
		}
	})

	t.Run("TamperedCiphertext", func(t *testing.T) {
		cipherText, err := Encrypt("my secret text")
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		// Tamper with the ciphertext by changing the last character
		tampered := cipherText[:len(cipherText)-2] + "A="
		_, err = Decrypt(tampered)
		if err != ErrDecryption {
			t.Errorf("expected ErrDecryption for tampered ciphertext, got %v", err)
		}
	})
}

