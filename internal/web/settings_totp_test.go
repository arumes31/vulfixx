package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
	"github.com/pquerna/otp/totp"
)

func TestVerifyTOTPHandler_Detailed(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/settings/totp/verify", nil)
		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("ParseFormError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		// Providing a body that fails ParseForm (invalid % encoding)
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader("totp_code=test%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, 1, false)

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "/settings") {
			t.Errorf("expected redirect to /settings, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("NoSecret", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(""))

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "/settings") {
			t.Errorf("expected redirect to /settings, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("SetupMissing", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		secret := "JBSWY3DPEHPK3PXP"
		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET totp_secret = NULL WHERE id = $1 AND is_totp_enabled = FALSE")).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=Setup+expired+or+invalid") {
			t.Errorf("expected redirect with setup expired error, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("SetupExpired", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		secret := "JBSWY3DPEHPK3PXP"
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET totp_secret = NULL WHERE id = $1 AND is_totp_enabled = FALSE")).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix() - 601
		_ = session.Save(req, httptest.NewRecorder())

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=Setup+expired+or+invalid") {
			t.Errorf("expected redirect with setup expired error, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("TooManyAttempts", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		secret := "JBSWY3DPEHPK3PXP"
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET totp_secret = NULL WHERE id = $1 AND is_totp_enabled = FALSE")).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 5
		_ = session.Save(req, httptest.NewRecorder())

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=Too+many+attempts") {
			t.Errorf("expected redirect with too many attempts error, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("ValidationError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		secret := "invalid secret" // This will cause ValidateCustom to error
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		_ = session.Save(req, httptest.NewRecorder())

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=Invalid+TOTP+code") {
			t.Errorf("expected redirect with invalid totp error, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("InvalidCode", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		secret := "JBSWY3DPEHPK3PXP"
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		form := url.Values{"totp_code": {"000000"}} // Incorrect code
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 2
		_ = session.Save(req, httptest.NewRecorder())

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=Invalid+TOTP+code") {
			t.Errorf("expected redirect with invalid totp error, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}

		// Verify session attempt increment
		sessionAfter, _ := app.SessionStore.Get(req, "vulfixx-session")
		if sessionAfter.Values["totp_setup_attempts"].(int) != 3 {
			t.Errorf("expected attempts to be 3, got %v", sessionAfter.Values["totp_setup_attempts"])
		}
	})

	t.Run("DBUpdateError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app := setupTestApp(t, mock)
		app.Now = func() time.Time { return fixedTime }

		userID := 1
		secret := "JBSWY3DPEHPK3PXP"
		code, _ := totp.GenerateCode(secret, fixedTime)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET is_totp_enabled = TRUE WHERE id = $1")).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		form := url.Values{"totp_code": {code}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		_ = session.Save(req, httptest.NewRecorder())

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=Failed+to+enable+2FA") {
			t.Errorf("expected redirect with failed to enable error, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app := setupTestApp(t, mock)
		app.Now = func() time.Time { return fixedTime }

		userID := 1
		secret := "JBSWY3DPEHPK3PXP"
		code, _ := totp.GenerateCode(secret, fixedTime)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT totp_secret FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET is_totp_enabled = TRUE WHERE id = $1")).
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).
			WithArgs(userID, "totp_enabled", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		form := url.Values{"totp_code": {code}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 1
		_ = session.Save(req, httptest.NewRecorder())

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}

		// Verify session cleanup and verification flag
		sessionAfter, _ := app.SessionStore.Get(req, "vulfixx-session")
		if _, exists := sessionAfter.Values["totp_setup_ts"]; exists {
			t.Errorf("expected totp_setup_ts to be deleted")
		}
		if _, exists := sessionAfter.Values["totp_setup_attempts"]; exists {
			t.Errorf("expected totp_setup_attempts to be deleted")
		}
		if sessionAfter.Values["totp_verified"] != true {
			t.Errorf("expected totp_verified to be true")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
