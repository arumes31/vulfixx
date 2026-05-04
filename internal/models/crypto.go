package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

func getCipher() (cipher.AEAD, error) {
	rawKey := os.Getenv("SESSION_KEY")
	if len(rawKey) == 0 {
		return nil, errors.New("missing SESSION_KEY")
	}

	// Derive a 32-byte key using HKDF
	hash := sha256.New
	salt := []byte("vulfixx-salt-v1") // Application-wide salt
	info := []byte("webhook-encryption")
	hkdfReader := hkdf.New(hash, []byte(rawKey), salt, info)

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func EncryptWebhook(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	gcm, err := getCipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptWebhook(cryptoText string) (string, error) {
	if cryptoText == "" {
		return "", nil
	}
	gcm, err := getCipher()
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
