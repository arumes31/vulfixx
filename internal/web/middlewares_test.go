package web

import (
	"context"
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestAuthMiddleware(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	InitSession()

	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr.Code)
		}
	})

	t.Run("AuthenticatedButUnverified", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		// We can't easily save the session back to the recorder in a unit test without a real response writer
		// But store.Get uses the request context/cookies.
		
		// Actually, store.Get works with the request.
		// To simulate a cookie, we'd need to sign it.
		// Easier to just mock GetUserID if we could.
		
		// But let's try to set the value in the session.
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)
		
		// Re-create request with cookie
		req = httptest.NewRequest("GET", "/dashboard", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}
		
		mock.ExpectQuery("SELECT is_email_verified").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified"}).AddRow(false))
		
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req)
		if rr2.Code != http.StatusForbidden {
			t.Errorf("expected 403 forbidden, got %d", rr2.Code)
		}
	})

	t.Run("AuthenticatedAndVerified", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/dashboard", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}
		
		mock.ExpectQuery("SELECT is_email_verified").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified"}).AddRow(true))
		
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestAdminMiddleware(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	InitSession()

	handler := AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 unauthorized, got %d", rr.Code)
		}
	})

	t.Run("AuthenticatedNotAdmin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/admin", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}
		
		mock.ExpectQuery("SELECT is_admin").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(false))
		
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req)
		if rr2.Code != http.StatusForbidden {
			t.Errorf("expected 403 forbidden, got %d", rr2.Code)
		}
	})

	t.Run("AuthenticatedIsAdmin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/admin", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}
		
		mock.ExpectQuery("SELECT is_admin").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(true))
		
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestProxyMiddleware(t *testing.T) {
	newHandler := func() http.Handler {
		return ProxyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.Context().Value(clientIPKey).(string)
			w.Header().Set("X-Client-IP", ip)
			w.WriteHeader(http.StatusOK)
		}))
	}

	t.Run("DirectConnection", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rr := httptest.NewRecorder()
		newHandler().ServeHTTP(rr, req)
		if rr.Header().Get("X-Client-IP") != "1.2.3.4" {
			t.Errorf("expected 1.2.3.4, got %s", rr.Header().Get("X-Client-IP"))
		}
	})

	t.Run("CloudflareProxy", func(t *testing.T) {
		t.Setenv("ENABLE_CLOUDFLARE_PROXY", "true")
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("CF-Connecting-IP", "5.6.7.8")
		rr := httptest.NewRecorder()
		newHandler().ServeHTTP(rr, req)
		if rr.Header().Get("X-Client-IP") != "5.6.7.8" {
			t.Errorf("expected 5.6.7.8, got %s", rr.Header().Get("X-Client-IP"))
		}
	})

	t.Run("TrustedProxyXFF", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "127.0.0.1")
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "9.10.11.12, 127.0.0.1")
		rr := httptest.NewRecorder()
		newHandler().ServeHTTP(rr, req)
		if rr.Header().Get("X-Client-IP") != "9.10.11.12" {
			t.Errorf("expected 9.10.11.12, got %s", rr.Header().Get("X-Client-IP"))
		}
	})

	t.Run("TrustedProxyXRealIP", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Real-IP", "172.16.0.1")
		rr := httptest.NewRecorder()
		newHandler().ServeHTTP(rr, req)
		if rr.Header().Get("X-Client-IP") != "172.16.0.1" {
			t.Errorf("expected 172.16.0.1, got %s", rr.Header().Get("X-Client-IP"))
		}
	})

	t.Run("UntrustedProxy", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "127.0.0.1")
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		req.Header.Set("X-Forwarded-For", "9.10.11.12")
		rr := httptest.NewRecorder()
		newHandler().ServeHTTP(rr, req)
		if rr.Header().Get("X-Client-IP") == "9.10.11.12" {
			t.Errorf("did not expect 9.10.11.12 from untrusted proxy")
		}
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	handler := RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), clientIPKey, "1.1.1.1")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("RateLimited", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), clientIPKey, "2.2.2.2")
		req = req.WithContext(ctx)
		
		// Burst is 10. Do 11 requests.
		for i := 0; i < 11; i++ {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if i < 10 && rr.Code != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", i, rr.Code)
			}
			if i == 10 && rr.Code != http.StatusTooManyRequests {
				t.Errorf("request %d: expected 429, got %d", i, rr.Code)
			}
		}
	})
}
