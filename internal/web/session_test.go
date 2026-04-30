package web

import (
	"testing"
)

func TestInitSession(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	secure := true

	store := InitSession(key, secure)

	if store == nil {
		t.Fatal("expected session store to be initialized, got nil")
	}

	if GetSessionStore() != store {
		t.Fatal("expected GetSessionStore() to return the same store")
	}

	if store.Options.Secure != secure {
		t.Errorf("expected Secure option to be %v, got %v", secure, store.Options.Secure)
	}

	if store.Options.HttpOnly != true {
		t.Errorf("expected HttpOnly option to be true, got %v", store.Options.HttpOnly)
	}
}
