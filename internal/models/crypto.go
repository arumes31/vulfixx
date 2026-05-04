package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

func getCipher() (cipher.AEAD, error) {
	key := os.Getenv("SESSION_KEY")
	if len(key) == 0 {
		return nil, errors.New("missing SESSION_KEY")
	}
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		padded := make([]byte, 32)
		copy(padded, key)
		key = string(padded)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func EncryptWebhook(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	gcm, err := getCipher()
	if err != nil {
		return plaintext
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func DecryptWebhook(cryptoText string) string {
	if cryptoText == "" {
		return ""
	}
	gcm, err := getCipher()
	if err != nil {
		return cryptoText
	}
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return cryptoText
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return cryptoText
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return cryptoText
	}
	return string(plaintext)
}
