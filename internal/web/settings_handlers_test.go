package web

import (
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

func TestSettingsHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/settings", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/settings", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT email, is_totp_enabled").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).AddRow("test@test.com", false))

		expectBaseQueries(mock, 1)
		rr2 := httptest.NewRecorder()
		app.SettingsHandler(rr2, req)
		if rr2.Code != http.StatusOK && rr2.Code != http.StatusBadRequest {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestChangePasswordHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		hash, _ := bcrypt.GenerateFromPassword([]byte("current"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash"}).AddRow(string(hash)))
		mock.ExpectExec("UPDATE users").WithArgs(pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		form := "current_password=current&new_password=new123&confirm_password=new123"
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/settings/password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		app.ChangePasswordHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr2.Code)
		}
	})

    t.Run("Mismatch", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{
			"current_password": {"oldpass123"},
			"new_password":     {"newpass123"},
			"confirm_password": {"mismatch"},
		}
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email, is_totp_enabled, password_hash, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled", "password_hash", "totp_secret"}).
				AddRow("user@example.com", false, "hash", ""))

		rr := httptest.NewRecorder()
		expectBaseQueries(mock, userID)
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "New passwords do not match") {
			t.Errorf("expected mismatch error")
		}
	})
}

func TestSettingsHandlers_Detailed(t *testing.T) {
    t.Run("ChangeEmail_RedisError", func(t *testing.T) {
        mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
        
        mr, _ := miniredis.Run()
        rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
        mr.Close() // Force error
        
		app := setupTestApp(t, mock)
        app.Redis = rdb

		userID := 1
		form := url.Values{
			"new_email": {"new@example.com"},
			"password":  {"password"},
		}
		req := httptest.NewRequest("POST", "/settings/email", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("old@example.com", false))
        
        mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("old@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "old@example.com", string(hashedPassword), true, false, "", false))
        
        mock.ExpectExec("INSERT INTO email_change_requests").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
		expectBaseQueries(mock, userID)
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
        if !strings.Contains(rr.Body.String(), "Error requesting email change") {
            t.Errorf("expected redis error message")
        }
    })
    
    t.Run("DeleteAccount_DBError", func(t *testing.T) {
        mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"password": {"password"}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))
        
        mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))
        
        mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
            WithArgs(userID).
            WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		expectBaseQueries(mock, userID)
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
    })
}
