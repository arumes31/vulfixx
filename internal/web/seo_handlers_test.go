package web

import (
	"cve-tracker/internal/db"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestSitemapHandler_DatabaseError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Mock DB error
	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnError(errors.New("db error"))

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK even on DB error, got %v", rr.Code)
	}
	// Should still contain static pages
	if !strings.Contains(rr.Body.String(), "/login") {
		t.Errorf("Response body missing static pages on DB error")
	}
}

func TestSitemapHandler_ScanError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Mock scan error by returning wrong type
	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow(123, "not-a-time"))

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK even on scan error, got %v", rr.Code)
	}
}

func TestSitemapHandler_RowsError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Mock rows error
	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow("CVE-1", time.Now()).
			RowError(0, errors.New("rows error")))

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK even on rows error, got %v", rr.Code)
	}
}

func TestRobotsHandler(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected string
	}{
		{
			name:     "Default/Empty",
			baseURL:  "",
			expected: "User-agent: *\nAllow: /\nSitemap: http://localhost:8080/sitemap.xml\n",
		},
		{
			name:     "Custom URL",
			baseURL:  "https://vulfixx.com",
			expected: "User-agent: *\nAllow: /\nSitemap: https://vulfixx.com/sitemap.xml\n",
		},
		{
			name:     "Custom URL with trailing slash",
			baseURL:  "https://vulfixx.com/",
			expected: "User-agent: *\nAllow: /\nSitemap: https://vulfixx.com/sitemap.xml\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BASE_URL", tt.baseURL)

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

			if rr.Body.String() != tt.expected {
				t.Errorf("Expected body %q, got %q", tt.expected, rr.Body.String())
			}
		})
	}
}

func TestGetBaseURL(t *testing.T) {
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

func TestSitemapHandler_NoRedis(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	// Manual app setup without Redis
	app := &App{
		Pool: mock,
	}

	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow("CVE-NO-REDIS", time.Now()))

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "CVE-NO-REDIS") {
		t.Errorf("Response body missing expected CVE ID")
	}
}

func TestSitemapHandler_RedisSetError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Close redis to trigger error on Set
	app.Redis.Close()

	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow("CVE-REDIS-ERR", time.Now()))

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK even on Redis error, got %v", rr.Code)
	}
}
