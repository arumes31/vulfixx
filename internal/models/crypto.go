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
	"sync"

	"golang.org/x/crypto/hkdf"
)

// HKDF derivation dominates the cost of every webhook encrypt/decrypt, but the result
// only changes when SESSION_KEY does. Cache the AEAD, keyed on a digest of the raw key
// so a key rotation invalidates the entry without holding a second copy of the secret.
var (
	cipherCacheMu     sync.RWMutex
	cipherCacheKeySum [sha256.Size]byte
	cipherCacheAEAD   cipher.AEAD
)

func getCipher() (cipher.AEAD, error) {
	rawKey := os.Getenv("SESSION_KEY")
	if len(rawKey) == 0 {
		return nil, errors.New("missing SESSION_KEY")
	}
	keySum := sha256.Sum256([]byte(rawKey))

	cipherCacheMu.RLock()
	if cipherCacheAEAD != nil && cipherCacheKeySum == keySum {
		cached := cipherCacheAEAD
		cipherCacheMu.RUnlock()
		return cached, nil
	}
	cipherCacheMu.RUnlock()

	cipherCacheMu.Lock()
	defer cipherCacheMu.Unlock()
	if cipherCacheAEAD != nil && cipherCacheKeySum == keySum {
		return cipherCacheAEAD, nil
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
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherCacheKeySum = keySum
	cipherCacheAEAD = gcm
	return gcm, nil
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
