package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestMiddlewares_Consolidated(t *testing.T) {
	t.Run("SecurityHeaders", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.SecurityHeadersMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		headers := []string{
			"X-Content-Type-Options",
			"X-Frame-Options",
			"Strict-Transport-Security",
			"Referrer-Policy",
			"X-XSS-Protection",
			"Content-Security-Policy",
		}

		for _, h := range headers {
			if rr.Header().Get(h) == "" {
				t.Errorf("expected header %s to be set", h)
			}
		}
	})

	t.Run("ProxyMiddleware_Cloudflare", func(t *testing.T) {
		t.Setenv("ENABLE_CLOUDFLARE_PROXY", "true")
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(clientIPKey); val != nil {
				capturedIP = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("CF-Connecting-IP", "1.2.3.4")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "1.2.3.4" {
			t.Errorf("expected client IP 1.2.3.4, got %s", capturedIP)
		}
	})

	t.Run("ProxyMiddleware_TrustedProxy", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(clientIPKey); val != nil {
				capturedIP = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.1")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "5.6.7.8" {
			t.Errorf("expected client IP 5.6.7.8, got %s", capturedIP)
		}
	})

	t.Run("ProxyMiddleware_UntrustedProxy", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "127.0.0.1")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(clientIPKey); val != nil {
				capturedIP = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.1.1.1:12345"
		req.Header.Set("X-Forwarded-For", "5.6.7.8")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "1.1.1.1" {
			t.Errorf("expected client IP 1.1.1.1 (RemoteAddr), got %s", capturedIP)
		}
	})

	t.Run("RateLimitMiddleware_Trigger", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.RateLimitMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		// Limiter has burst of 10.
		for i := 0; i < 10; i++ {
			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("request %d should have been allowed", i)
			}
		}

		// 11th request should be rate limited
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429 Too Many Requests, got %d", rr.Code)
		}
	})

	t.Run("AuthMiddleware_Unverified", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_email_verified, is_totp_enabled, onboarding_completed").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(false, false, true))

		rr2 := httptest.NewRecorder()
		app.AuthMiddleware(nextHandler).ServeHTTP(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rr2.Code)
		}
	})

	t.Run("AdminMiddleware_NonAdmin", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/admin", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/admin", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_admin").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(false))

		rr2 := httptest.NewRecorder()
		app.AdminMiddleware(nextHandler).ServeHTTP(rr2, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr2.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rr2.Code)
		}
	})
}

func TestIsTrustedProxy(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies string
		ip             string
		expected       bool
	}{
		{"EmptyEnv_Loopback", "", "127.0.0.1", true},
		{"EmptyEnv_LoopbackV6", "", "::1", true},
		{"EmptyEnv_NonLoopback", "", "1.1.1.1", false},
		{"InvalidIP", "10.0.0.1", "invalid", false},
		{"EmptySegments", "127.0.0.1,,10.0.0.1", "10.0.0.1", true},
		{"InvalidCIDR", "invalid_cidr,10.0.0.1", "10.0.0.1", true},
		{"InvalidCIDRFormat", "10.0.0.0/invalid,10.0.0.1", "10.0.0.1", true},
		{"InvalidAddrInEnv", "10.0.0.256,10.0.0.1", "10.0.0.1", true},
		{"CIDR_Match", "192.168.1.0/24", "192.168.1.5", true},
		{"CIDR_NoMatch", "192.168.1.0/24", "192.168.2.5", false},
		{"SingleIP_NoMatch", "10.0.0.1", "10.0.0.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", tt.trustedProxies)
			if got := isTrustedProxy(tt.ip); got != tt.expected {
				t.Errorf("isTrustedProxy(%q) with TRUSTED_PROXIES=%q = %v, want %v", tt.ip, tt.trustedProxies, got, tt.expected)
			}
		})
	}
}

func TestProxyMiddleware_Extra(t *testing.T) {
	t.Run("XRealIP", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(clientIPKey); val != nil {
				capturedIP = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "9.9.9.9")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "9.9.9.9" {
			t.Errorf("expected client IP 9.9.9.9, got %s", capturedIP)
		}
	})

	t.Run("NoPort", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "127.0.0.1")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(clientIPKey); val != nil {
				capturedIP = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1" // No port
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "127.0.0.1" {
			t.Errorf("expected client IP 127.0.0.1, got %s", capturedIP)
		}
	})

	t.Run("Cloudflare_MissingHeader", func(t *testing.T) {
		t.Setenv("ENABLE_CLOUDFLARE_PROXY", "true")
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if val := r.Context().Value(clientIPKey); val != nil {
				capturedIP = val.(string)
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		// No CF-Connecting-IP
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "10.0.0.1" {
			t.Errorf("expected client IP 10.0.0.1, got %s", capturedIP)
		}
	})
}
