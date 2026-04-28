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
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
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

		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_subscriptions WHERE user_id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		mock.ExpectBegin()
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
	})
}

func TestHandleAlertAction(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	mr, _ := db.SetupTestRedis()
	defer mr.Close()
	app := setupTestApp(t, mock)
	app.Redis = db.RedisClient

	t.Run("Acknowledge", func(t *testing.T) {
		token := "action-token"
		data, _ := json.Marshal(map[string]interface{}{"user_id": 1, "cve_id": 100, "keyword": "test"})
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
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock

		mr, _ := miniredis.Run()
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

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
		dataJSON, _ := json.Marshal(data)
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
	})
}
