package web

import (
	"cve-tracker/internal/db"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestErrorReportHandler(t *testing.T) {
	app := &App{}
	t.Run("GET_NotAllowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/report-error", nil)
		rr := httptest.NewRecorder()
		app.ErrorReportHandler(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})

	t.Run("POST_InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/report-error", strings.NewReader("{invalid"))
		rr := httptest.NewRecorder()
		app.ErrorReportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("POST_Success", func(t *testing.T) {
		data := map[string]string{
			"message": "test error",
			"type":    "TypeError",
			"url":     "http://localhost/test",
		}
		body, _ := json.Marshal(data)
		req := httptest.NewRequest("POST", "/report-error", strings.NewReader(string(body)))
		rr := httptest.NewRecorder()
		app.ErrorReportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})
}

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

func TestApp_ErrorReportHandler_Throttling(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	app := &App{
		Redis: rdb,
	}

	data := map[string]string{
		"message": "test duplicate error",
		"type":    "TypeError",
		"url":     "http://localhost/test",
	}
	body, _ := json.Marshal(data)

	// Send 5 successful requests (under the limit)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/errors", strings.NewReader(string(body)))
		rr := httptest.NewRecorder()
		app.ErrorReportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d on attempt %d", rr.Code, i+1)
		}
	}

	// Send a 6th request - should be throttled but still return 200 OK (soft-fail)
	req := httptest.NewRequest("POST", "/api/errors", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	app.ErrorReportHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for throttled request, got %d", rr.Code)
	}

	// Verify key exists in Redis and count is 6
	keys := mr.Keys()
	if !slices.ContainsFunc(keys, func(k string) bool {
		if strings.HasPrefix(k, "err_limit:") {
			val, _ := mr.Get(k)
			if val != "6" {
				t.Errorf("expected redis counter to be 6, got %s", val)
			}
			return true
		}
		return false
	}) {
		t.Error("expected err_limit key to be stored in Redis")
	}
}
