package web

import (
	"bytes"
	"context"
	"cve-tracker/internal/db"

	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestHealthHandlers(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("HealthzHandler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		rr := httptest.NewRecorder()
		app.HealthzHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("ReadyzHandler_Success", func(t *testing.T) {
		mock.ExpectPing()
		mr, _ := db.SetupTestRedis()
		defer mr.Close()
		app.Redis = db.RedisClient

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()
		app.ReadyzHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("ReadyzHandler_DBDown", func(t *testing.T) {
		mock.ExpectPing().WillReturnError(errors.New("db down"))
		mr, _ := db.SetupTestRedis()
		defer mr.Close()
		app.Redis = db.RedisClient

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()
		app.ReadyzHandler(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 Service Unavailable, got %d", rr.Code)
		}
	})
}

func TestUpdateCVENoteHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("Success_Private", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "test notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "test notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cve_notes")).WithArgs(1, pgxmock.AnyArg(), 1, "test notes").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).WithArgs(1, "cve_note_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr2 := httptest.NewRecorder()
		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})

	t.Run("Success_Team", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "team notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		session.Values["active_team_id"] = 10
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "team notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS")).WithArgs(10, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cve_notes")).WithArgs(1, pgxmock.AnyArg(), 1, "team notes").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).WithArgs(1, "cve_note_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr2 := httptest.NewRecorder()
		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
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
		// No teams query expected here because the request is not authenticated via session (RenderTemplate skips it)
		reqPost := httptest.NewRequest("POST", "/alert-action?token="+token+"&action=acknowledge", nil)
		rrPost := httptest.NewRecorder()
		app.HandleAlertAction(rrPost, reqPost)
		if rrPost.Code != http.StatusOK {
			t.Errorf("POST expected 200 OK, got %d", rrPost.Code)
		}
	})
}

func TestLoginHandler_Failures(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("InvalidCredentials", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, email").WithArgs("fail@test.com").WillReturnError(errors.New("invalid credentials"))

		req := httptest.NewRequest("POST", "/login", bytes.NewReader([]byte("email=fail@test.com&password=wrong")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)
		if rr.Code != http.StatusOK { // Re-renders login page with error
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})
}

func TestMiddlewares_Extra(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("AuthMiddleware_Unverified", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_email_verified").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"is_email_verified"}).AddRow(false))

		rr2 := httptest.NewRecorder()
		app.AuthMiddleware(nextHandler).ServeHTTP(rr2, req)
		if rr2.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rr2.Code)
		}
	})

	t.Run("AdminMiddleware_NonAdmin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/admin", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_admin").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(false))

		rr2 := httptest.NewRecorder()
		app.AdminMiddleware(nextHandler).ServeHTTP(rr2, req)
		if rr2.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rr2.Code)
		}
	})
}

func TestAdminHandlers_Coverage(t *testing.T) {
	t.Run("AdminUserManagementHandler_Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/admin/users", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		session.Values["is_admin"] = true
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/admin/users", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT id, email, is_email_verified, is_admin, created_at FROM users").WillReturnRows(pgxmock.NewRows([]string{"id", "email", "is_email_verified", "is_admin", "created_at"}).
			AddRow(1, "admin@test.com", true, true, time.Now()))
		expectBaseQueries(mock, 1)

		rr2 := httptest.NewRecorder()
		app.AdminUserManagementHandler(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})

	t.Run("AdminDeleteUserHandler_Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/admin/users/delete", bytes.NewReader([]byte("id=2&csrf_token=valid")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		session.Values["is_admin"] = true
		session.Values["admin_csrf_token"] = "valid"
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/admin/users/delete", bytes.NewReader([]byte("id=2&csrf_token=valid")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectExec("DELETE FROM users").WithArgs(2).WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr2 := httptest.NewRecorder()
		app.AdminDeleteUserHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr2.Code)
		}
	})
}

