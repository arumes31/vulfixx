package web

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
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
	"github.com/jackc/pgx/v5"
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

		mock.ExpectQuery("(?is)SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.published_date").
			WithArgs(1, 0.0, "").
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "published_date"}).
				AddRow("CVE-2024-RSS", "RSS Test", 8.0, time.Now()))

		req, _ := http.NewRequest("GET", "/feed?token="+token, nil)
		rr := httptest.NewRecorder()
		app.RSSFeedHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		if rr.Header().Get("Content-Type") != "application/rss+xml" {
			t.Errorf("wrong content type")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		token := "invalid"
		mock.ExpectQuery("SELECT id FROM users WHERE rss_feed_token = \\$1").
			WithArgs(token).
			WillReturnError(pgx.ErrNoRows)

		req, _ := http.NewRequest("GET", "/feed?token="+token, nil)
		rr := httptest.NewRecorder()
		app.RSSFeedHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
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

		// GET renders confirmation page (legacy query param)
		req := httptest.NewRequest("GET", "/alert-action?token="+token+"&action=acknowledge", nil)
		rr := httptest.NewRecorder()
		app.HandleAlertAction(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		// POST actually writes to DB with status 'in_progress'
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_cve_status")).WithArgs(1, 100).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).WithArgs(1, "remediation", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		form := url.Values{
			"token":  {token},
			"action": {"acknowledge"},
		}
		reqPost := httptest.NewRequest("POST", "/alert-action", strings.NewReader(form.Encode()))
		reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		form := url.Values{
			"token":  {token},
			"action": {action},
		}
		reqPost := httptest.NewRequest("POST", "/alert-action", strings.NewReader(form.Encode()))
		reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rrPost := httptest.NewRecorder()

		mock.ExpectExec("INSERT INTO user_cve_status").
			WithArgs(userID, 123).
			WillReturnError(fmt.Errorf("db error"))

		app.HandleAlertAction(rrPost, reqPost)

		if rrPost.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rrPost.Code)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestSubscriptionHandlers_Detailed(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)
	app := setupTestApp(t, mock)

	t.Run("SubscriptionsHandler_GET", func(t *testing.T) {
		mock.ExpectQuery("(?is)SELECT us.id, us.keyword, us.min_severity, us.webhook_url,.*FROM user_subscriptions").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "keyword", "min_severity", "webhook_url", "slack_webhook_url", "teams_webhook_url", "enable_email", "enable_webhook", "enable_slack", "enable_teams", "enable_browser_push", "aggregation_mode", "filter_logic", "team_id"}).
				AddRow(1, "test", 5.0, "", "", "", true, true, false, false, false, "instant", "", nil))

		expectBaseQueries(mock, 1)

		req, _ := http.NewRequest("GET", "/subscriptions", nil)
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.SubscriptionsHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("SubscriptionsHandler_POST_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		form := url.Values{
			"keyword":      {"new-keyword"},
			"min_severity": {"7.5"},
			"enable_email": {"on"},
		}

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT max_subscriptions FROM users WHERE id = \\$1 FOR UPDATE").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"max_subscriptions"}).AddRow(5))
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_subscriptions WHERE user_id = \\$1").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectExec("INSERT INTO user_subscriptions").WithArgs(1, "new-keyword", 7.5, "", "", "", true, false, false, false, false, "instant", "").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "subscription_added", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req, _ := http.NewRequest("POST", "/subscriptions", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Requested-With", "XMLHttpRequest") // Make it AJAX
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.SubscriptionsHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK (AJAX success), got %d. Body: %s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	// Regression: Slack/Teams webhook URLs must be encrypted at rest so the worker
	// (which calls models.DecryptWebhook on read) can recover them. Previously they
	// were stored as plaintext, so decryption failed and Slack/Teams alerts silently
	// never fired.
	t.Run("SubscriptionsHandler_POST_EncryptsSlackWebhook", func(t *testing.T) {
		t.Setenv("SESSION_KEY", "THIS_IS_A_MOCK_SESSION_KEY_32_BY")
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		const slackURL = "https://hooks.slack.com/services/T000/B000/XXXXXXXX"
		form := url.Values{
			"keyword":           {"kw"},
			"min_severity":      {"5"},
			"enable_email":      {"on"},
			"enable_slack":      {"on"},
			"slack_webhook_url": {slackURL},
		}

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT max_subscriptions FROM users WHERE id = \\$1 FOR UPDATE").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"max_subscriptions"}).AddRow(5))
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_subscriptions WHERE user_id = \\$1").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectExec("INSERT INTO user_subscriptions").
			WithArgs(1, "kw", 5.0, "", encryptedWebhookArg{plaintext: slackURL, t: t}, "", true, false, true, false, false, "instant", "").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "subscription_added", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req, _ := http.NewRequest("POST", "/subscriptions", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.SubscriptionsHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	// Complex boolean filters are now wired end-to-end: a malformed filter_logic
	// expression must be rejected before any DB write.
	t.Run("SubscriptionsHandler_POST_RejectsInvalidFilter", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		form := url.Values{
			"keyword":      {"kw"},
			"min_severity": {"5"},
			"enable_email": {"on"},
			"filter_logic": {"epss >"}, // truncated term -> invalid
		}
		// No DB expectations: the handler must reject before touching the database.

		req, _ := http.NewRequest("POST", "/subscriptions", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.SubscriptionsHandler(rr, req)

		if !strings.Contains(rr.Body.String(), "Invalid filter logic") {
			t.Errorf("expected invalid filter logic rejection, got body: %s", rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unexpected DB calls for invalid filter: %v", err)
		}
	})

	t.Run("DeleteSubscriptionHandler_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		mock.ExpectExec("DELETE FROM user_subscriptions").WithArgs(1, 1).WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "subscription_deleted", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req, _ := http.NewRequest("POST", "/subscriptions/delete", strings.NewReader("id=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.DeleteSubscriptionHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("UpdateSubscriptionHandler_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		payload := map[string]interface{}{
			"id":               42,
			"keyword":          "updated-keyword",
			"min_severity":     8.0,
			"webhook_url":      "http://example.com/webhook",
			"enable_email":     true,
			"enable_webhook":   true,
			"aggregation_mode": "hourly",
		}
		body, _ := json.Marshal(payload)

		// 1. SELECT user_id FROM user_subscriptions WHERE id = $1 -> returns owner 1
		mock.ExpectQuery("(?i)SELECT user_id FROM user_subscriptions WHERE id = \\$1").
			WithArgs(42).
			WillReturnRows(pgxmock.NewRows([]string{"user_id"}).AddRow(1))

		// 2. UPDATE user_subscriptions
		mock.ExpectExec("(?i)UPDATE user_subscriptions").
			WithArgs("updated-keyword", 8.0, "http://example.com/webhook", "", "", true, true, false, false, false, "hourly", "", 42, 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		// 3. INSERT INTO user_activity_logs
		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(1, "subscription_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req, _ := http.NewRequest("POST", "/subscriptions/update", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.UpdateSubscriptionHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

// encryptedWebhookArg is a pgxmock argument matcher asserting that the stored
// webhook value is not the plaintext and decrypts back to the expected plaintext.
type encryptedWebhookArg struct {
	plaintext string
	t         *testing.T
}

func (e encryptedWebhookArg) Match(v interface{}) bool {
	s, ok := v.(string)
	if !ok {
		e.t.Errorf("expected stored webhook to be a string, got %T", v)
		return false
	}
	if s == e.plaintext {
		e.t.Errorf("webhook URL stored as plaintext, expected encrypted ciphertext")
		return false
	}
	dec, err := models.DecryptWebhook(s)
	if err != nil {
		e.t.Errorf("stored webhook URL failed to decrypt: %v", err)
		return false
	}
	if dec != e.plaintext {
		e.t.Errorf("decrypted webhook = %q, want %q", dec, e.plaintext)
		return false
	}
	return true
}
