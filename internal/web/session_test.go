package web

import (
	"cve-tracker/internal/db"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/sessions"
	"github.com/redis/go-redis/v9"
)

func TestInitSession(t *testing.T) {
	key := []byte("THIS_IS_A_MOCK_SESSION_KEY_32_BY")
	secure := true

	store := InitSession(key, secure)

	if store == nil {
		t.Fatal("expected session store to be initialized, got nil")
	}

	if GetSessionStore() != store {
		t.Fatal("expected GetSessionStore() to return the same store")
	}

	cookieStore, ok := store.(*sessions.CookieStore)
	if !ok {
		t.Fatal("expected session store to be *sessions.CookieStore")
	}

	if cookieStore.Options.Secure != secure {
		t.Errorf("expected Secure option to be %v, got %v", secure, cookieStore.Options.Secure)
	}

	if cookieStore.Options.HttpOnly != true {
		t.Errorf("expected HttpOnly option to be true, got %v", cookieStore.Options.HttpOnly)
	}
}

type dummyRedisProvider struct {
	db.RedisProvider
}

func TestInitRedisSession(t *testing.T) {
	t.Run("NilClient", func(t *testing.T) {
		_, err := InitRedisSession(nil, []byte("key"), true)
		if err == nil {
			t.Error("expected error for nil redis client")
		}
	})

	t.Run("InvalidClientType", func(t *testing.T) {
		var dummy db.RedisProvider = dummyRedisProvider{}
		_, err := InitRedisSession(dummy, []byte("key"), true)
		if err == nil {
			t.Error("expected error for invalid redis client type")
		}
	})

	t.Run("Success", func(t *testing.T) {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		rdb := redis.NewClient(&redis.Options{
			Addr: mr.Addr(),
		})
		defer rdb.Close()

		store, err := InitRedisSession(rdb, []byte("THIS_IS_A_MOCK_SESSION_KEY_32_BY"), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected session store to be initialized, got nil")
		}
	})
}

