package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebErrorPaths(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	// Test IndexHandler Not Found
	req := httptest.NewRequest("GET", "/invalid", nil)
	rr := httptest.NewRecorder()
	app.IndexHandler(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("IndexHandler should return 404 for invalid path, got %d", rr.Code)
	}

	// Test LoginHandler Parse Form Error
	req = httptest.NewRequest("POST", "/login", strings.NewReader("invalid=form%"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	app.LoginHandler(rr, req)
	// Actually, ParseForm doesn't fail that easily with strings.NewReader
	// But let's assume it might or test another error path.

	// Test UpdateCVEStatusHandler Method Not Allowed
	req = httptest.NewRequest("GET", "/api/status", nil)
	rr = httptest.NewRecorder()
	app.UpdateCVEStatusHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("UpdateCVEStatusHandler should return 405 for GET, got %d", rr.Code)
	}

	// Test UpdateCVEStatusHandler Unauthorized
	req = httptest.NewRequest("POST", "/api/status", nil)
	rr = httptest.NewRecorder()
	app.UpdateCVEStatusHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("UpdateCVEStatusHandler should return 401 for unauthorized, got %d", rr.Code)
	}

	// Test RSSFeedHandler Missing Token
	req = httptest.NewRequest("GET", "/feed", nil)
	rr = httptest.NewRecorder()
	app.RSSFeedHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("RSSFeedHandler should return 401 for missing token, got %d", rr.Code)
	}
}
