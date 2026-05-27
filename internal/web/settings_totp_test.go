package web

import (
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
	"github.com/pquerna/otp/totp"
)

func TestTOTPHandlers_Detailed(t *testing.T) {
	t.Run("GenerateTOTPHandler_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		userID := 1
		req := httptest.NewRequest("GET", "/settings/totp/generate", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("test@example.com"))

		mock.ExpectExec("UPDATE users SET totp_secret = \\$1 WHERE id = \\$2").
			WithArgs(pgxmock.AnyArg(), userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.GenerateTOTPHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Manual Secret") {
			t.Errorf("expected response to contain Manual Secret")
		}

		// Verify session
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		if session.Values["totp_setup_ts"] != fixedTime.Unix() {
			t.Errorf("expected totp_setup_ts %d, got %v", fixedTime.Unix(), session.Values["totp_setup_ts"])
		}
	})

	t.Run("GenerateTOTPHandler_Unauthenticated", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/settings/totp/generate", nil)
		rr := httptest.NewRecorder()
		app.GenerateTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d", rr.Code)
		}
	})

	t.Run("GenerateTOTPHandler_UserNotFound", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		req := httptest.NewRequest("GET", "/settings/totp/generate", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.GenerateTOTPHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
	})

	t.Run("GenerateTOTPHandler_SaveSecretError", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		req := httptest.NewRequest("GET", "/settings/totp/generate", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("test@example.com"))

		mock.ExpectExec("UPDATE users SET totp_secret = \\$1 WHERE id = \\$2").
			WithArgs(pgxmock.AnyArg(), userID).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.GenerateTOTPHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
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
		code, _ := totp.GenerateCode(secret, fixedTime)

		userID := 1
		form := url.Values{"totp_code": {code}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		_ = session.Save(req, httptest.NewRecorder())

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec("UPDATE users SET is_totp_enabled = TRUE WHERE id = \\$1").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(userID, "totp_enabled", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d", rr.Code)
		}

		session2, _ := app.SessionStore.Get(req, "vulfixx-session")
		if session2.Values["totp_verified"] != true {
			t.Errorf("expected totp_verified to be true in session")
		}
	})

	t.Run("VerifyTOTPHandler_Unauthenticated", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/settings/totp/verify", nil)
		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d", rr.Code)
		}
	})

	t.Run("VerifyTOTPHandler_ParseFormError", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader("totp_code=test%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d", rr.Code)
		}
	})

	t.Run("VerifyTOTPHandler_NoSecret", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(""))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d", rr.Code)
		}
	})

	t.Run("VerifyTOTPHandler_DBError_Secret", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d", rr.Code)
		}
	})

	t.Run("VerifyTOTPHandler_NoSetupTS", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		// Session has no totp_setup_ts

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("secret"))

		mock.ExpectExec("UPDATE users SET totp_secret = NULL WHERE id = \\$1 AND is_totp_enabled = FALSE").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "expired") {
			t.Errorf("expected redirect with expired error, got %s", rr.Header().Get("Location"))
		}
	})

	t.Run("VerifyTOTPHandler_SetupExpired", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		userID := 1
		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix() - 700 // 700 seconds ago (> 600)
		_ = session.Save(req, httptest.NewRecorder())

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("secret"))

		mock.ExpectExec("UPDATE users SET totp_secret = NULL WHERE id = \\$1 AND is_totp_enabled = FALSE").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "expired") {
			t.Errorf("expected redirect with expired error, got %s", rr.Header().Get("Location"))
		}
	})

	t.Run("VerifyTOTPHandler_TooManyAttempts", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		userID := 1
		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 5
		_ = session.Save(req, httptest.NewRecorder())

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("secret"))

		mock.ExpectExec("UPDATE users SET totp_secret = NULL WHERE id = \\$1 AND is_totp_enabled = FALSE").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "Too+many+attempts") {
			t.Errorf("expected redirect with too many attempts error, got %s", rr.Header().Get("Location"))
		}
	})

	t.Run("VerifyTOTPHandler_InvalidCode", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		secret := "JBSWY3DPEHPK3PXP"
		userID := 1
		form := url.Values{"totp_code": {"000000"}} // Invalid code
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		_ = session.Save(req, httptest.NewRecorder())

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "Invalid+TOTP+code") {
			t.Errorf("expected redirect with invalid code error, got %s", rr.Header().Get("Location"))
		}

		session2, _ := app.SessionStore.Get(req, "vulfixx-session")
		if session2.Values["totp_setup_attempts"] != 1 {
			t.Errorf("expected totp_setup_attempts to be 1, got %v", session2.Values["totp_setup_attempts"])
		}
	})

	t.Run("VerifyTOTPHandler_DBEnableError", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)
		fixedTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
		app.Now = func() time.Time { return fixedTime }

		secret := "JBSWY3DPEHPK3PXP"
		code, _ := totp.GenerateCode(secret, fixedTime)

		userID := 1
		form := url.Values{"totp_code": {code}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = fixedTime.Unix()
		session.Values["totp_setup_attempts"] = 0
		_ = session.Save(req, httptest.NewRecorder())

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow(secret))

		mock.ExpectExec("UPDATE users SET is_totp_enabled = TRUE WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "Failed+to+enable") {
			t.Errorf("expected redirect with failed to enable error, got %s", rr.Header().Get("Location"))
		}
	})
}

func TestVerifyTOTPHandler_Extra(t *testing.T) {
	t.Run("VerifyTOTPHandler_InvalidSecretFormat", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_setup_ts"] = time.Now().Unix()
		session.Values["totp_setup_attempts"] = 0
		_ = session.Save(req, httptest.NewRecorder())

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("not-base32-junk!"))

		rr := httptest.NewRecorder()
		app.VerifyTOTPHandler(rr, req)

		if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "Invalid+TOTP+code") {
			t.Errorf("expected redirect with invalid code error due to bad secret, got %s", rr.Header().Get("Location"))
		}
	})
}

func TestSettingsHandler_Detailed(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/settings", nil)
		rr := httptest.NewRecorder()
		app.SettingsHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d", rr.Code)
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		req := httptest.NewRequest("GET", "/settings", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.SettingsHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
	})
}
