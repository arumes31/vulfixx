package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"strings"
)

func TestWebErrorPaths(t *testing.T) {
	t.Setenv("SESSION_KEY", "testkey")
	t.Setenv("CSRF_KEY", "0123456789abcdef0123456789abcdef")
	
	if os.Getenv("CI") == "true" {
		t.Skip("skipping integration test in CI")
	}

	if err := db.InitDB(); err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("InitDB failed (skipping): %v", err)
		} else {
			t.Fatalf("InitDB failed: %v", err)
		}
	}
	defer db.CloseDB()

	if err := db.InitRedis(); err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("InitRedis failed (skipping): %v", err)
		} else {
			t.Fatalf("InitRedis failed: %v", err)
		}
	}
	defer db.CloseRedis()

	InitSession()

	// Test IndexHandler Not Found
	req := httptest.NewRequest("GET", "/invalid", nil)
	rr := httptest.NewRecorder()
	IndexHandler(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("IndexHandler should return 404 for invalid path, got %d", rr.Code)
	}

	// Test LoginHandler Parse Form Error
	req = httptest.NewRequest("POST", "/login", strings.NewReader("invalid=form%"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	LoginHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("LoginHandler should return 400 for invalid form, got %d", rr.Code)
	}

	// Test UpdateCVEStatusHandler Method Not Allowed
	req = httptest.NewRequest("GET", "/api/status", nil)
	rr = httptest.NewRecorder()
	UpdateCVEStatusHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("UpdateCVEStatusHandler should return 405 for GET, got %d", rr.Code)
	}

	// Test UpdateCVEStatusHandler Unauthorized
	req = httptest.NewRequest("POST", "/api/status", nil)
	rr = httptest.NewRecorder()
	UpdateCVEStatusHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("UpdateCVEStatusHandler should return 401 for unauthorized, got %d", rr.Code)
	}

	// Test RSSFeedHandler Missing Token
	req = httptest.NewRequest("GET", "/feed", nil)
	rr = httptest.NewRecorder()
	RSSFeedHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("RSSFeedHandler should return 401 for missing token, got %d", rr.Code)
	}
}
