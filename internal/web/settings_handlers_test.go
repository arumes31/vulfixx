package web

import (
	"cve-tracker/internal/db"
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
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

func TestTOTPHandlers(t *testing.T) {
	t.Run("GenerateTOTPHandler_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		mock.ExpectQuery("SELECT email FROM users").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("test@example.com"))
		mock.ExpectExec("UPDATE users SET totp_secret").WithArgs(pgxmock.AnyArg(), 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		expectBaseQueries(mock, 1)

		req, _ := http.NewRequest("POST", "/settings/totp/generate", nil)
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.GenerateTOTPHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("VerifyTOTPHandler_InvalidCode", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		mock.ExpectQuery("SELECT totp_secret FROM users").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("SECRET"))

		form := url.Values{"totp_code": {"000000"}}
		req, _ := http.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, 1, false)
		
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }
		
		// Set setup values in session and persist them via cookie
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		
		rr := httptest.NewRecorder()
		if err := session.Save(req, rr); err != nil {
			t.Fatalf("session.Save: %v", err)
		}
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("VerifyTOTPHandler_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		secret := "JBSWY3DPEHPK3PXP"
		code, err := totp.GenerateCode(secret, fixedTime)
		if err != nil {
			t.Fatalf("failed to generate totp code: %v", err)
		}
		mock.ExpectQuery("SELECT totp_secret FROM users").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))
		mock.ExpectExec("UPDATE users SET is_totp_enabled = TRUE").WithArgs(1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "totp_enabled", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		form := url.Values{"totp_code": {code}}
		req, _ := http.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, 1, false)

		// Set setup values in session and persist them via cookie
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		
		rr := httptest.NewRecorder()
		if err := session.Save(req, rr); err != nil {
			t.Fatalf("session.Save: %v", err)
		}
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestSettingsHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
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
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestChangePasswordHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		hash, _ := bcrypt.GenerateFromPassword([]byte("current"), bcrypt.DefaultCost)
		// 1. Selection query in handler
		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).AddRow("test@test.com", false))

		// 2. auth.ChangePassword selection query
		mock.ExpectQuery("SELECT password_hash, is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hash), false, ""))

		// 3. auth.ChangePassword update
		mock.ExpectExec("UPDATE users").WithArgs(pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		// 4. LogActivity in handler
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "password_changed", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// 5. RenderTemplate in handler
		expectBaseQueries(mock, 1)

		form := "current_password=current&new_password=newpassword123&confirm_password=newpassword123"
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
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Mismatch", func(t *testing.T) {
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
			"current_password": {"oldpass123"},
			"new_password":     {"newpass123"},
			"confirm_password": {"mismatch"},
		}
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("user@example.com", false))

		expectBaseQueries(mock, userID)
		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "New passwords do not match") {
			t.Errorf("expected mismatch error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestSettingsHandlers_Detailed(t *testing.T) {
	t.Run("ChangeEmail_RedisError", func(t *testing.T) {
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

		// 1. Initial selection
		mock.ExpectQuery(regexp.QuoteMeta("SELECT email, is_totp_enabled FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("old@example.com", false))

			// 2. auth.Login
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, ''), is_admin FROM users WHERE email = $1")).
			WithArgs("old@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "old@example.com", string(hashedPassword), true, false, "", false))

			// 3. auth.RequestEmailChange
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO email_change_requests")).
			WithArgs(userID, "new@example.com", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// 4. Redis pipeline (FAILS)

		// 5. RenderTemplate
		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Error requesting email change") {
			t.Errorf("expected redis error message")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("DeleteAccount_DBError", func(t *testing.T) {
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
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
