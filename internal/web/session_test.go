package web

import (
	"cve-tracker/internal/db"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/sessions"
	"github.com/redis/go-redis/v9"
	"net/http"
	"net/http/httptest"
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

func TestSessionMethods(t *testing.T) {
	app := &App{
		SessionStore: sessions.NewCookieStore([]byte("secret")),
	}

	t.Run("GetActiveTeamID_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["team_id"] = 123

		// We need to save the session to a recorder to get the cookie
		rr := httptest.NewRecorder()
		if err := session.Save(req, rr); err != nil {
			t.Fatalf("failed to save session: %v", err)
		}
		req.AddCookie(rr.Result().Cookies()[0])

		id, ok := app.GetActiveTeamID(req)
		if !ok || id != 123 {
			t.Errorf("expected (123, true), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveTeamID_NilStore", func(t *testing.T) {
		nilApp := &App{SessionStore: nil}
		req, _ := http.NewRequest("GET", "/", nil)
		id, ok := nilApp.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetUserID_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 456

		rr := httptest.NewRecorder()
		if err := session.Save(req, rr); err != nil {
			t.Fatalf("failed to save session: %v", err)
		}
		req.AddCookie(rr.Result().Cookies()[0])

		id, ok := app.GetUserID(req)
		if !ok || id != 456 {
			t.Errorf("expected (456, true), got (%d, %v)", id, ok)
		}
	})

	t.Run("SetActiveTeamID_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		err := app.SetActiveTeamID(rr, req, 789)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify it was set by reading it back
		req.AddCookie(rr.Result().Cookies()[0])
		id, ok := app.GetActiveTeamID(req)
		if !ok || id != 789 {
			t.Errorf("expected (789, true), got (%d, %v)", id, ok)
		}
	})

	t.Run("IsAdmin", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["is_admin"] = true

		rr := httptest.NewRecorder()
		if err := session.Save(req, rr); err != nil {
			t.Fatalf("failed to save session: %v", err)
		}
		req.AddCookie(rr.Result().Cookies()[0])

		if !app.IsAdmin(req) {
			t.Error("expected IsAdmin to be true")
		}

		session, _ = app.SessionStore.Get(req, "vulfixx-session")
		session.Values["is_admin"] = false
		rr = httptest.NewRecorder()
		if err := session.Save(req, rr); err != nil {
			t.Fatalf("failed to save session: %v", err)
		}
		req.AddCookie(rr.Result().Cookies()[0])

		if app.IsAdmin(req) {
			t.Error("expected IsAdmin to be false")
		}
	})

	t.Run("TypeConversions", func(t *testing.T) {
		tests := []struct {
			val      any
			expected int
			ok       bool
		}{
			{int(1), 1, true},
			{int64(2), 2, true},
			{float64(3.0), 3, true},
			{float32(4.0), 4, true},
			{"string", 0, false},
			{nil, 0, false},
		}

		for _, tc := range tests {
			req, _ := http.NewRequest("GET", "/", nil)
			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["team_id"] = tc.val

			rr := httptest.NewRecorder()
			if err := session.Save(req, rr); err != nil {
				t.Fatalf("failed to save session: %v", err)
			}
			req.AddCookie(rr.Result().Cookies()[0])

			id, ok := app.GetActiveTeamID(req)
			if ok != tc.ok || id != tc.expected {
				t.Errorf("for %v: expected (%d, %v), got (%d, %v)", tc.val, tc.expected, tc.ok, id, ok)
			}
		}
	})
}

func TestGetSessionInt64(t *testing.T) {
	tests := []struct {
		val      any
		expected int64
		ok       bool
	}{
		{int(1), 1, true},
		{int64(2), 2, true},
		{float64(3.0), 3, true},
		{float32(4.0), 4, true},
		{"string", 0, false},
		{nil, 0, false},
	}

	for _, tc := range tests {
		got, ok := getSessionInt64(tc.val)
		if ok != tc.ok || got != tc.expected {
			t.Errorf("for %v: expected (%d, %v), got (%d, %v)", tc.val, tc.expected, tc.ok, got, ok)
		}
	}
}

func TestSessionMethods_Errors(t *testing.T) {
	app := &App{
		SessionStore: sessions.NewCookieStore([]byte("secret")),
	}

	t.Run("GetUserID_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "invalid"})
		id, ok := app.GetUserID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("GetActiveTeamID_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "invalid"})
		id, ok := app.GetActiveTeamID(req)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("IsAdmin_SessionError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "invalid"})
		if app.IsAdmin(req) {
			t.Error("expected IsAdmin to be false on session error")
		}
	})

	t.Run("SetActiveTeamID_NilStore", func(t *testing.T) {
		nilApp := &App{SessionStore: nil}
		err := nilApp.SetActiveTeamID(nil, nil, 1)
		if err == nil {
			t.Error("expected error for nil store")
		}
	})

	t.Run("SetActiveTeamID_GetError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "vulfixx-session", Value: "invalid"})
		err := app.SetActiveTeamID(httptest.NewRecorder(), req, 1)
		if err == nil {
			t.Error("expected error for invalid session cookie")
		}
	})
}

func TestSessionMethods_Missing(t *testing.T) {

	t.Run("GetUserID_NilStore", func(t *testing.T) {
		nilApp := &App{SessionStore: nil}
		id, ok := nilApp.GetUserID(nil)
		if ok || id != 0 {
			t.Errorf("expected (0, false), got (%d, %v)", id, ok)
		}
	})

	t.Run("IsAdmin_NilStore", func(t *testing.T) {
		nilApp := &App{SessionStore: nil}
		if nilApp.IsAdmin(nil) {
			t.Error("expected IsAdmin to be false for nil store")
		}
	})
}
