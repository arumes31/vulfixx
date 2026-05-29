package web

import (
	"cve-tracker/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

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
