package web

import (
	"cve-tracker/internal/db"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginHandler(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/login", nil)
		rr := httptest.NewRecorder()
		expectBaseQueries(mock, 0)
		app.LoginHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("POST_InvalidCredentials", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE").WithArgs("test@example.com").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("POST_Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE").WithArgs("test@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "test@example.com", string(hash), true, false, "", false))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=password"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr.Code)
		}
	})
}

func TestVerifyTOTPHandler(t *testing.T) {
	t.Run("InvalidCode", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader("totp_code=123456"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		session.Values["totp_setup_ts"] = time.Now().Unix()
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader("totp_code=123456"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("secret"))

		rr2 := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr2.Code)
		}
	})
}

func TestAuthHandlers_TOTP_Detailed(t *testing.T) {
	t.Run("Login_RequireTOTP", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		db.Pool = mock
		app := setupTestApp(t, mock)

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "user@example.com", string(hashedPassword), true, true, "SECRET", false))

		form := url.Values{"email": {"user@example.com"}, "password": {"password"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		expectBaseQueries(mock, 1)
		expectBaseQueries(mock, 1)
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

		form := url.Values{"totp_code": {code}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["pre_auth_user_id"] = 1
		session.Values["pre_auth_ts"] = time.Now().Unix()
		session.Values["pre_auth_attempts"] = 0
		rr_session := httptest.NewRecorder()
		if err := session.Save(req, rr_session); err != nil {
				t.Fatalf("session.Save: %v", err)
		}
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_totp_enabled", "totp_secret"}).AddRow(true, secret))

		mock.ExpectQuery("SELECT is_admin FROM users WHERE id = \\$1").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(false))

		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		rr := httptest.NewRecorder()
		expectBaseQueries(mock, 1)
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
		if err := session.Save(req, rr_session); err != nil {
				t.Fatalf("session.Save: %v", err)
		}
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_totp_enabled", "totp_secret"}).AddRow(true, secret))

		rr := httptest.NewRecorder()
		expectBaseQueries(mock, 1)
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
		rr_session := httptest.NewRecorder()
		if err := session.Save(req, rr_session); err != nil {
				t.Fatalf("session.Save: %v", err)
		}
		for _, c := range rr_session.Result().Cookies() {
			req.AddCookie(c)
		}

		app.Redis.Set(req.Context(), "totp_failures:"+req.RemoteAddr, 5, 0)

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
