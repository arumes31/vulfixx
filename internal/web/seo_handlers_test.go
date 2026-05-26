package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestSitemapHandler_Caching(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// 1. First request: Should query DB and populate cache
	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow("CVE-2023-CACHE", time.Now()))

	req1 := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr1 := httptest.NewRecorder()
	app.SitemapHandler(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr1.Code)
	}
	if !strings.Contains(rr1.Body.String(), "CVE-2023-CACHE") {
		t.Errorf("Response body missing expected CVE ID: %s", rr1.Body.String())
	}

	// 2. Second request: Should serve from cache, NOT query DB
	// miniredis was started in setupTestApp, so a.Redis is not nil and functional.
	req2 := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr2 := httptest.NewRecorder()
	app.SitemapHandler(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("Expected status OK for second request, got %v", rr2.Code)
	}
	if rr2.Body.String() != rr1.Body.String() {
		t.Errorf("Expected cached response to match original response")
	}

	// Ensure all expectations were met (none for the second call)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestRobotsHandler(t *testing.T) {
	origVal, origSet := os.LookupEnv("BASE_URL")
	os.Setenv("BASE_URL", "http://localhost:8080")
	t.Cleanup(func() {
		if origSet {
			os.Setenv("BASE_URL", origVal)
		} else {
			os.Unsetenv("BASE_URL")
		}
	})

	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	rr := httptest.NewRecorder()
	app.RobotsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected Content-Type text/plain, got %v", contentType)
	}

	expectedBody := "User-agent: *\nAllow: /\nSitemap: http://localhost:8080/sitemap.xml\n"
	if rr.Body.String() != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, rr.Body.String())
	}
}

func TestGetBaseURL(t *testing.T) {
	// Save current BASE_URL to restore it later if necessary, but t.Setenv does it.

	tests := []struct {
		name     string
		baseURL  string
		expected string
	}{
		{
			name:     "Default value",
			baseURL:  "",
			expected: "http://localhost:8080",
		},
		{
			name:     "Custom URL",
			baseURL:  "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "Custom URL with trailing slash",
			baseURL:  "https://example.com/",
			expected: "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BASE_URL", tt.baseURL)

			got := GetBaseURL()
			if got != tt.expected {
				t.Errorf("GetBaseURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}
