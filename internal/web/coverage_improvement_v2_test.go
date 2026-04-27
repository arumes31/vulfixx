package web

import (
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthHandlers_TOTP_V2(t *testing.T) {
	t.Run("Login_RequireTOTP", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

		// Mock Login
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "user@example.com", string(hashedPassword), true, true, "SECRET", false))

		form := url.Values{"email": {"user@example.com"}, "password": {"password"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mock.ExpectExec("INSERT INTO user_activity_logs").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "name=\"totp_code\"") {
			t.Errorf("expected body to contain TOTP input")
		}
	})

	t.Run("Login_VerifyTOTP_Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		secret := "JBSWY3DPEHPK3PXP"
		code, _ := totp.GenerateCode(secret, time.Now())

		// Set pre-auth session
		form := url.Values{"totp_code": {code}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["pre_auth_user_id"] = 1
		session.Values["pre_auth_ts"] = time.Now().Unix()
		session.Values["pre_auth_attempts"] = 0
		rr_session := httptest.NewRecorder()
		session.Save(req, rr_session)
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_totp_enabled", "totp_secret"}).AddRow(true, secret))

		mock.ExpectQuery("SELECT is_admin FROM users WHERE id = \\$1").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(false))

		mock.ExpectExec("INSERT INTO user_activity_logs").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
	})

	t.Run("Login_VerifyTOTP_Failure", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		secret := "JBSWY3DPEHPK3PXP"

		form := url.Values{"totp_code": {"000000"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["pre_auth_user_id"] = 1
		session.Values["pre_auth_ts"] = time.Now().Unix()
		session.Values["pre_auth_attempts"] = 0
		rr_session := httptest.NewRecorder()
		session.Save(req, rr_session)
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_totp_enabled", "totp_secret"}).AddRow(true, secret))

		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("Login_VerifyTOTP_Expired", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["pre_auth_user_id"] = 1
		session.Values["pre_auth_ts"] = time.Now().Unix() - 600
		rr_session := httptest.NewRecorder()
		session.Save(req, rr_session)
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

    t.Run("Login_VerifyTOTP_TooManyAttempts", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["pre_auth_user_id"] = 1
		session.Values["pre_auth_ts"] = time.Now().Unix()
		session.Values["pre_auth_attempts"] = 5
		rr_session := httptest.NewRecorder()
		session.Save(req, rr_session)
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
        if !strings.Contains(rr.Body.String(), "Too many attempts") {
            t.Errorf("expected too many attempts error")
        }
	})
}

func TestHealthHandlers_V2(t *testing.T) {
	t.Run("Readyz_Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		mr, _ := miniredis.Run()
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

		app := &App{Pool: mock, Redis: rdb}
		mock.ExpectPing()

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()

		app.ReadyzHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("Readyz_Failure", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		mr, _ := miniredis.Run()
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

		app := &App{Pool: mock, Redis: rdb}
		mock.ExpectPing().WillReturnError(fmt.Errorf("db down"))

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()

		app.ReadyzHandler(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", rr.Code)
		}
	})
}

func TestSettingsHandlers_V2(t *testing.T) {
	t.Run("ChangePassword_Mismatch", func(t *testing.T) {
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
		setSessionUser(t, app, req, userID)

		mock.ExpectQuery("SELECT email, is_totp_enabled, password_hash, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled", "password_hash", "totp_secret"}).
				AddRow("user@example.com", false, "hash", ""))

		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "New passwords do not match") {
			t.Errorf("expected mismatch error")
		}
	})

    t.Run("ChangePassword_AuthError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{
			"current_password": {"wrongpass"},
			"new_password":     {"newpass123"},
			"confirm_password": {"newpass123"},
		}
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID)

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpass"), bcrypt.DefaultCost)

		mock.ExpectQuery("SELECT email, is_totp_enabled, password_hash, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled", "password_hash", "totp_secret"}).
				AddRow("user@example.com", false, string(hashedPassword), ""))
        
        // Inside auth.ChangePassword
        mock.ExpectQuery("SELECT password_hash, is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).
				AddRow(string(hashedPassword), false, ""))

		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
        if !strings.Contains(rr.Body.String(), "invalid current password") {
            t.Errorf("expected invalid password error")
        }
	})
    
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
		setSessionUser(t, app, req, userID)

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("old@example.com", false))
        
        // auth.Login
        mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("old@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "old@example.com", string(hashedPassword), true, false, "", false))
        
        // auth.RequestEmailChange
        mock.ExpectExec("INSERT INTO email_change_requests").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
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
		setSessionUser(t, app, req, userID)

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))
        
        // auth.Login
        mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))
        
        mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
            WithArgs(userID).
            WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
    })
}

func TestSubscriptionHandlers_V2(t *testing.T) {
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
		setSessionUser(t, app, req, userID)

		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM user_subscriptions WHERE user_id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		mock.ExpectExec("INSERT INTO user_subscriptions").
			WithArgs(userID, "test", 7.0, "", true, false).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mock.ExpectExec("INSERT INTO user_activity_logs").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
		app.SubscriptionsHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr.Code)
		}
	})

	t.Run("HandleAlertAction_DBError", func(t *testing.T) {
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
		mr.Set("alert_action:"+token, string(dataJSON))

		// GET confirmation page
		reqGet := httptest.NewRequest("GET", "/alert-action?token="+token+"&action="+action, nil)
		rrGet := httptest.NewRecorder()
		app.HandleAlertAction(rrGet, reqGet)
		if rrGet.Code != http.StatusOK {
			t.Errorf("GET: expected 200, got %d", rrGet.Code)
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
