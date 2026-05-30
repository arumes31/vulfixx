package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
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

func TestApp_SessionMethods(t *testing.T) {
	app := &App{
		SessionStore: sessions.NewCookieStore([]byte("test-secret")),
	}

	t.Run("GetActiveUserID_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 123

		id, ok := app.GetActiveUserID(req)
		if !ok || id != 123 {
			t.Errorf("expected (123, true), got (%d, %v)", id, ok)
		}

		// Test GetUserID as well since it calls GetActiveUserID
		id, ok = app.GetUserID(req)
		if !ok || id != 123 {
			t.Errorf("GetUserID: expected (123, true), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveUserID_NilStore", func(t *testing.T) {
		emptyApp := &App{}
		req, _ := http.NewRequest("GET", "/", nil)
		id, ok := emptyApp.GetActiveUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveTeamID_Success", func(t *testing.T) {
		tests := []struct {
			name     string
			val      any
			expected int
		}{
			{"int", 456, 456},
			{"int64", int64(456), 456},
			{"float64", float64(456.0), 456},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req, _ := http.NewRequest("GET", "/", nil)
				session, _ := app.SessionStore.Get(req, "vulfixx-session")
				session.Values["team_id"] = tt.val

				id, ok := app.GetActiveTeamID(req)
				if !ok || id != tt.expected {
					t.Errorf("expected (%d, true), got (%d, %v)", tt.expected, id, ok)
				}
			})
		}
	})

	t.Run("GetActiveTeamID_NilStore", func(t *testing.T) {
		emptyApp := &App{}
		req, _ := http.NewRequest("GET", "/", nil)
		id, ok := emptyApp.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveTeamID_MissingValue", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		id, ok := app.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveTeamID_WrongType", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["team_id"] = "string"

		id, ok := app.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("SetActiveTeamID_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		err := app.SetActiveTeamID(rr, req, 789)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify it was set
		id, ok := app.GetActiveTeamID(req)
		if !ok || id != 789 {
			t.Errorf("expected (789, true), got (%d, %v)", id, ok)
		}
	})

	t.Run("IsAdmin_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["is_admin"] = true

		if !app.IsAdmin(req) {
			t.Error("expected IsAdmin to return true")
		}

		session.Values["is_admin"] = false
		if app.IsAdmin(req) {
			t.Error("expected IsAdmin to return false")
		}
	})
}

func TestGetSessionHelpers(t *testing.T) {
	t.Run("getSessionInt", func(t *testing.T) {
		tests := []struct {
			input    any
			expected int
			ok       bool
		}{
			{1, 1, true},
			{int64(2), 2, true},
			{float64(3.0), 3, true},
			{float32(4.0), 4, true},
			{nil, 0, false},
			{"string", 0, false},
		}
		for _, tt := range tests {
			res, ok := getSessionInt(tt.input)
			if ok != tt.ok || res != tt.expected {
				t.Errorf("getSessionInt(%v) = (%d, %v), want (%d, %v)", tt.input, res, ok, tt.expected, tt.ok)
			}
		}
	})

	t.Run("getSessionInt64", func(t *testing.T) {
		tests := []struct {
			input    any
			expected int64
			ok       bool
		}{
			{1, 1, true},
			{int64(2), 2, true},
			{float64(3.0), 3, true},
			{float32(4.0), 4, true},
			{nil, 0, false},
			{"string", 0, false},
		}
		for _, tt := range tests {
			res, ok := getSessionInt64(tt.input)
			if ok != tt.ok || res != tt.expected {
				t.Errorf("getSessionInt64(%v) = (%d, %v), want (%d, %v)", tt.input, res, ok, tt.expected, tt.ok)
			}
		}
	})
}

func TestApp_SessionMethods_Errors(t *testing.T) {
	// CookieStore.Get returns an error if the securecookie fails to decode (e.g. invalid key)
	store := sessions.NewCookieStore([]byte("very-secret-key"))
	app := &App{SessionStore: store}

	t.Run("GetActiveUserID_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		// Add a cookie that will fail to decode because it was encrypted with a different key (if it was even encrypted)
		// Or just a garbage cookie
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "garbage"})

		id, ok := app.GetActiveUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false) on session error, got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveTeamID_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "garbage"})

		id, ok := app.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false) on session error, got (%d, %v)", id, ok)
		}
	})

	t.Run("IsAdmin_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "garbage"})

		if app.IsAdmin(req) {
			t.Error("expected IsAdmin to return false on session error")
		}
	})

	t.Run("SetActiveTeamID_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "garbage"})
		rr := httptest.NewRecorder()

		err := app.SetActiveTeamID(rr, req, 123)
		if err == nil {
			t.Error("expected error on SetActiveTeamID with bad session")
		}
	})
}
