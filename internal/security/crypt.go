package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

var (
	ErrEmptyPlainText  = errors.New("plaintext cannot be empty")
	ErrEmptyCipherText = errors.New("ciphertext cannot be empty")
	ErrDecryption      = errors.New("decryption failed")
)

// getEncryptionKey derives a 32-byte key from the ENCRYPTION_KEY environment variable.
// If the variable is empty, it returns an error.
func getEncryptionKey() ([]byte, error) {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		return nil, errors.New("ENCRYPTION_KEY is empty; keyStr must not be empty")
	}
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:], nil
}

// Encrypt encrypts plain text using AES-256-GCM.
func Encrypt(plainText string) (string, error) {
	if plainText == "" {
		return "", ErrEmptyPlainText
	}

	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts AES-256-GCM cipher text.
func Decrypt(cipherTextStr string) (string, error) {
	if cipherTextStr == "" {
		return "", ErrEmptyCipherText
	}

	cipherText, err := base64.StdEncoding.DecodeString(cipherTextStr)
	if err != nil {
		return "", ErrDecryption
	}

	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", ErrDecryption
	}

	nonce, actualCipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainTextBytes, err := gcm.Open(nil, nonce, actualCipherText, nil)
	if err != nil {
		return "", ErrDecryption
	}

	return string(plainTextBytes), nil
}
