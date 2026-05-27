package web

import (
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)


func TestChangePasswordHandler(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/settings/password", nil)
		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d to %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		app := setupTestApp(t, mock)
		userID := 999
		req := httptest.NewRequest("POST", "/settings/password", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("user not found"))

		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d to %s", rr.Code, rr.Header().Get("Location"))
		}
	})

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

		hash, err := auth.HashPassword("current")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}
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

	t.Run("ValidationFailure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		app := setupTestApp(t, mock)
		userID := 1
		form := url.Values{
			"current_password": {"oldpass123"},
			"new_password":     {"short"},
			"confirm_password": {"short"},
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
		if !strings.Contains(rr.Body.String(), "New password must be at least 8 characters.") {
			t.Errorf("expected validation error")
		}
	})

	t.Run("IncorrectCurrentPassword", func(t *testing.T) {
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
			"current_password": {"wrongpass"},
			"new_password":     {"newpass123"},
			"confirm_password": {"newpass123"},
		}
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("user@example.com", false))

		// auth.ChangePassword query
		mock.ExpectQuery("SELECT password_hash, is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).
				AddRow("somehash", false, ""))

		expectBaseQueries(mock, userID)
		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Current password is incorrect") {
			t.Errorf("expected incorrect password error")
		}
	})

	t.Run("InvalidTOTP", func(t *testing.T) {
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
			"confirm_password": {"newpass123"},
			"totp_code":        {"123456"},
		}
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword("oldpass123")

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("user@example.com", true))

		// auth.ChangePassword query
		mock.ExpectQuery("SELECT password_hash, is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).
				AddRow(string(hashedPassword), true, "secret"))

		expectBaseQueries(mock, userID)
		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid or missing 2FA code") {
			t.Errorf("expected TOTP error")
		}
	})

	t.Run("UnexpectedAuthError", func(t *testing.T) {
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
			"confirm_password": {"newpass123"},
		}
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword("oldpass123")

		mock.ExpectQuery("SELECT email, is_totp_enabled FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("user@example.com", false))

		// auth.ChangePassword query
		mock.ExpectQuery("SELECT password_hash, is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).
				AddRow(string(hashedPassword), false, ""))

		// UPDATE fails
		mock.ExpectExec("UPDATE users").WithArgs(pgxmock.AnyArg(), userID).
			WillReturnError(fmt.Errorf("db error"))

		expectBaseQueries(mock, userID)
		rr := httptest.NewRecorder()
		app.ChangePasswordHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Unable to change password. Please try again later.") {
			t.Errorf("expected generic error message")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestSettingsHandlers_Detailed(t *testing.T) {
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

		hashedPassword, err := auth.HashPassword("password")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}

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

func TestChangeEmailHandler(t *testing.T) {
	t.Run("MethodNotAllowed", func(t *testing.T) {
		app := setupTestApp(t, nil)
		req := httptest.NewRequest("GET", "/settings/email", nil)
		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
		}
	})

	t.Run("Unauthorized", func(t *testing.T) {
		app := setupTestApp(t, nil)
		req := httptest.NewRequest("POST", "/settings/email", nil)
		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		app := setupTestApp(t, mock)
		userID := 1
		req := httptest.NewRequest("POST", "/settings/email", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT email, is_totp_enabled FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnError(fmt.Errorf("user not found"))

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
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
		form := url.Values{
			"new_email": {"invalid-email"},
			"password":  {"password"},
		}
		req := httptest.NewRequest("POST", "/settings/email", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT email, is_totp_enabled FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("old@example.com", false))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid email format") {
			t.Errorf("expected validation error message")
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
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
			"new_email": {"new@example.com"},
			"password":  {"wrong-password"},
		}
		req := httptest.NewRequest("POST", "/settings/email", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword("correct-password")

		mock.ExpectQuery(regexp.QuoteMeta("SELECT email, is_totp_enabled FROM users WHERE id = $1")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("old@example.com", false))

		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, ''), is_admin FROM users WHERE email = $1")).
			WithArgs("old@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "old@example.com", string(hashedPassword), true, false, "", false))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid password") {
			t.Errorf("expected invalid password message")
		}
	})

	t.Run("RedisError", func(t *testing.T) {
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

		hashedPassword, err := auth.HashPassword("password")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}

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

	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		mr, _ := miniredis.Run()
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

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

		hashedPassword, _ := auth.HashPassword("password")

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

		// 4. LogActivity
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).
			WithArgs(userID, "email_change_requested", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// 5. RenderTemplate
		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Email change requested") {
			t.Errorf("expected success message, got: %s", rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
	t.Run("ParseFormError", func(t *testing.T) {
		app := setupTestApp(t, nil)
		userID := 1
		// Providing a body that fails ParseForm (invalid % encoding)
		req := httptest.NewRequest("POST", "/settings/email", strings.NewReader("new_email=test%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
	})

	t.Run("RequestEmailChangeError", func(t *testing.T) {
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
			"new_email": {"new@example.com"},
			"password":  {"password"},
		}
		req := httptest.NewRequest("POST", "/settings/email", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword("password")

		mock.ExpectQuery(regexp.QuoteMeta("SELECT email, is_totp_enabled FROM users WHERE id = ")).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).
				AddRow("old@example.com", false))

		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, ''), is_admin FROM users WHERE email = ")).
			WithArgs("old@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "old@example.com", string(hashedPassword), true, false, "", false))

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO email_change_requests")).
			WithArgs(userID, "new@example.com", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(fmt.Errorf("db error"))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.ChangeEmailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Error requesting email change") {
			t.Errorf("expected error requesting email change message")
		}
	})
}

func TestDeleteAccountHandler(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/settings/delete", nil)
		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("InvalidMethod", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/settings/delete", nil)
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		req := httptest.NewRequest("POST", "/settings/delete", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("not found"))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
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
		form := url.Values{"password": {"wrong"}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		// auth.Login will return error because password doesn't match
		// We need to provide the real hash for Argon2id to fail
		hashedPassword, _ := auth.HashPassword("correct")
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid password") {
			t.Errorf("expected 'Invalid password' error in body")
		}
	})

	t.Run("Success", func(t *testing.T) {
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
		password := "correct_password"
		form := url.Values{"password": {password}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword(password)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))

		mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/register" {
			t.Errorf("expected redirect to /register, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}

		// Verify session is cleared (MaxAge = -1)
		found := false
		for _, cookie := range rr.Result().Cookies() {
			if cookie.Name == "vulfixx-session" && cookie.MaxAge < 0 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected session cookie to be cleared (MaxAge < 0)")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
