package models

import (
	"sync"
	"testing"
)

// setSessionKey points SESSION_KEY at key for the duration of the test and restores
// whatever was there before, including the unset case.
func setSessionKey(t *testing.T, key string) {
	t.Helper()
	t.Setenv("SESSION_KEY", key)
}

func TestGetCipherCachesPerKey(t *testing.T) {
	setSessionKey(t, "cache-key-one")

	first, err := getCipher()
	if err != nil {
		t.Fatalf("getCipher: %v", err)
	}
	second, err := getCipher()
	if err != nil {
		t.Fatalf("getCipher (second call): %v", err)
	}
	if first != second {
		t.Error("expected the cached AEAD to be reused for an unchanged SESSION_KEY")
	}

	// Rotating the key must invalidate the cache rather than hand back a cipher
	// derived from the old secret.
	t.Setenv("SESSION_KEY", "cache-key-two")
	third, err := getCipher()
	if err != nil {
		t.Fatalf("getCipher after rotation: %v", err)
	}
	if third == second {
		t.Error("expected a new AEAD after SESSION_KEY changed")
	}
}

// A value encrypted under one key must not decrypt under another. This guards against
// the cache handing back a stale cipher after rotation.
func TestWebhookCipherRespectsKeyRotation(t *testing.T) {
	setSessionKey(t, "rotation-key-one")

	ciphertext, err := EncryptWebhook("https://hooks.example.com/abc")
	if err != nil {
		t.Fatalf("EncryptWebhook: %v", err)
	}

	t.Setenv("SESSION_KEY", "rotation-key-two")
	if _, err := DecryptWebhook(ciphertext); err == nil {
		t.Error("expected decryption to fail after the key was rotated")
	}

	t.Setenv("SESSION_KEY", "rotation-key-one")
	got, err := DecryptWebhook(ciphertext)
	if err != nil {
		t.Fatalf("DecryptWebhook with the original key: %v", err)
	}
	if got != "https://hooks.example.com/abc" {
		t.Errorf("round-trip mismatch: got %q", got)
	}
}

// Exercises the RWMutex under -race; the cache is read from every webhook
// encrypt/decrypt and those run concurrently in the worker.
func TestGetCipherConcurrent(t *testing.T) {
	setSessionKey(t, "concurrent-key")

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if _, err := getCipher(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent getCipher: %v", err)
	}
}
