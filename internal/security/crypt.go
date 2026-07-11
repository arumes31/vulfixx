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
	"sync"
)

var (
	ErrEmptyPlainText  = errors.New("plaintext cannot be empty")
	ErrEmptyCipherText = errors.New("ciphertext cannot be empty")
	ErrDecryption      = errors.New("decryption failed")
)

var aeadCache sync.Map

// getAEAD retrieves or creates a cipher.AEAD for the current ENCRYPTION_KEY.
// We cache it using a sync.Map keyed by the environment variable value to
// avoid recomputing the AES block and GCM instances on every encryption/decryption,
// while remaining safe for isolated tests that alter the ENCRYPTION_KEY.
func getAEAD() (cipher.AEAD, error) {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if keyStr == "" {
		return nil, errors.New("ENCRYPTION_KEY is empty; keyStr must not be empty")
	}

	if cached, ok := aeadCache.Load(keyStr); ok {
		return cached.(cipher.AEAD), nil
	}

	hash := sha256.Sum256([]byte(keyStr))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	aeadCache.Store(keyStr, gcm)
	return gcm, nil
}

// Encrypt encrypts plain text using AES-256-GCM.
func Encrypt(plainText string) (string, error) {
	if plainText == "" {
		return "", ErrEmptyPlainText
	}

	gcm, err := getAEAD()
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

	gcm, err := getAEAD()
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
