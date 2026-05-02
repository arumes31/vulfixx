package web

import (
	"context"
	"cve-tracker/internal/db"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestRSSFeedHandler(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("Success", func(t *testing.T) {
		token := "rss-token-123"
		mock.ExpectQuery("SELECT id FROM users WHERE rss_feed_token = \\$1").
			WithArgs(token).
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

		mock.ExpectQuery("SELECT DISTINCT c.cve_id").
			WithArgs(1, 0.0, "").
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "published_date"}).
				AddRow("CVE-2024-RSS", "RSS Test", 8.0, time.Now()))

		req, _ := http.NewRequest("GET", "/feed?token="+token, nil)
		rr := httptest.NewRecorder()
		app.RSSFeedHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if rr.Header().Get("Content-Type") != "application/rss+xml" {
			t.Errorf("wrong content type")
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		token := "invalid"
		mock.ExpectQuery("SELECT id FROM users WHERE rss_feed_token = \\$1").
			WithArgs(token).
			WillReturnError(sql.ErrNoRows)

		req, _ := http.NewRequest("GET", "/feed?token="+token, nil)
		rr := httptest.NewRecorder()
		app.RSSFeedHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
		}
	})
}

func TestHandleAlertAction(t *testing.T) {
	t.Run("Acknowledge", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		mr, err := db.SetupTestRedis()
		if err != nil {
			t.Fatalf("failed to setup redis: %v", err)
		}
		defer mr.Close()
		app := setupTestApp(t, mock)
		app.Redis = db.RedisClient

		token := "action-token"
		data, err := json.Marshal(map[string]interface{}{"user_id": 1, "cve_id": 100, "keyword": "test"})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		db.RedisClient.Set(context.Background(), "alert_action:"+token, data, time.Hour)

		// GET renders confirmation page
		req := httptest.NewRequest("GET", "/alert-action?token="+token+"&action=acknowledge", nil)
		rr := httptest.NewRecorder()
		app.HandleAlertAction(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		// POST actually writes to DB with status 'in_progress'
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_cve_status")).WithArgs(1, 100).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).WithArgs(1, "remediation", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		reqPost := httptest.NewRequest("POST", "/alert-action?token="+token+"&action=acknowledge", nil)
		rrPost := httptest.NewRecorder()
		app.HandleAlertAction(rrPost, reqPost)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rrPost.Code != http.StatusOK {
			t.Errorf("POST expected 200 OK, got %d", rrPost.Code)
		}
	})

	t.Run("DBError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		defer func() { _ = rdb.Close() }()

		app := setupTestApp(t, mock)
		app.Redis = rdb

		userID := 1
		token := "test-token"
		action := "acknowledge"

		data := map[string]interface{}{
			"user_id": userID,
			"cve_id":  123,
			"keyword": "test",
		}
		dataJSON, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if err := mr.Set("alert_action:"+token, string(dataJSON)); err != nil {
			t.Fatalf("mr.Set: %v", err)
		}

		// POST execution with DB error
		reqPost := httptest.NewRequest("POST", "/alert-action?token="+token+"&action="+action, nil)
		rrPost := httptest.NewRecorder()

		mock.ExpectExec("INSERT INTO user_cve_status").
			WithArgs(userID, 123).
			WillReturnError(fmt.Errorf("db error"))

		app.HandleAlertAction(rrPost, reqPost)

		if rrPost.Code != http.StatusInternalServerError {
			t.Errorf("POST: expected 500, got %d", rrPost.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
