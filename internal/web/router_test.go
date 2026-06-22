package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cve-tracker/internal/config"

	"github.com/pashagolub/pgxmock/v3"
)

func TestRoutes_CSRFKeyValidation(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	t.Run("EmptyCSRFKey", func(t *testing.T) {
		cfg := &config.Config{
			CSRFKey: "",
		}
		_, err := app.Routes(cfg)
		if err == nil {
			t.Error("expected error for empty CSRFKey, got nil")
		}
	})

	t.Run("ShortCSRFKey", func(t *testing.T) {
		cfg := &config.Config{
			CSRFKey: "short-key",
		}
		_, err := app.Routes(cfg)
		if err == nil {
			t.Error("expected error for short CSRFKey, got nil")
		}
	})
}

func TestRoutes_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	cfg := &config.Config{
		CSRFKey:      "01234567890123456789012345678912", // 32 bytes
		SecureCookie: false,
		SentryDSN:    "http://test@sentry.local/1",
	}

	handler, err := app.Routes(cfg)
	if err != nil {
		t.Fatalf("expected successful routes construction, got: %v", err)
	}

	if handler == nil {
		t.Error("expected returned http.Handler to be non-nil")
	}
}

func TestStaticFileHandler(t *testing.T) {
	handler := staticFileHandler(http.Dir("."))

	t.Run("BlocksDirectoryListingWithSlash", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/static/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected StatusNotFound (404) for directory listing, got %d", w.Code)
		}
	})

	t.Run("BlocksDirectoryListingWithEmptyPath", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/static/any", nil)
		w := httptest.NewRecorder()

		// Manually set URL Path to empty to trigger fallback
		r.URL.Path = ""

		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected StatusNotFound (404) for empty path directory listing, got %d", w.Code)
		}
	})
}

func TestRouter_CSPReportCSRFBypass(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	cfg := &config.Config{
		CSRFKey:      "01234567890123456789012345678912", // 32 bytes
		SecureCookie: false,
	}

	handler, err := app.Routes(cfg)
	if err != nil {
		t.Fatalf("failed to construct routes: %v", err)
	}

	t.Run("GET_RejectedWith405", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/csp-report", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
		}
	})

	t.Run("POST_UnsupportedMIME_RejectedWith415", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", nil)
		req.Header.Set("Content-Type", "text/plain")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("expected 415 Unsupported Media Type, got %d", rr.Code)
		}
	})

	t.Run("POST_CSPReportMIME_BypassesCSRF", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", nil)
		req.Header.Set("Content-Type", "application/csp-report")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Bypassing CSRF means it goes to rate limiter or CSPReportHandler.
		// Since we didn't send a valid body, the handler returns 400 Bad Request instead of 403 Forbidden (CSRF block) or 415.
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request from CSPReportHandler, got %d", rr.Code)
		}
	})

	t.Run("POST_JSONMIME_BypassesCSRF", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", nil)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request from CSPReportHandler, got %d", rr.Code)
		}
	})
}
