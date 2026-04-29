package web

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestSubscriptionHandlers(t *testing.T) {
	t.Run("SubscriptionsHandler_Post_Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		
		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()
		
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{
			"keyword":      {"test"},
			"min_severity": {"7.0"},
			"enable_email": {"on"},
			"csrf_token":   {"dummy"},
		}
		req := httptest.NewRequest("POST", "/subscriptions", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_subscriptions WHERE user_id = \\$1 FOR UPDATE").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		mock.ExpectExec("INSERT INTO user_subscriptions").
			WithArgs(userID, "test", 7.0, "", true, false).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		rr := httptest.NewRecorder()
		app.SubscriptionsHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
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
		defer rdb.Close()

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
