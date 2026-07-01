package web

import (
	"context"
	"crypto/sha256"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/pquerna/otp/totp"
)

func TestConfirmEmailChangeHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	// auth.ConfirmEmailChange uses db.Pool
	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()

	t.Run("MissingToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/confirm-email-change", nil)
		rr := httptest.NewRecorder()
		app.ConfirmEmailChangeHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email").WithArgs("invalid").WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		req, _ := http.NewRequest("GET", "/confirm-email-change?token=invalid", nil)
		rr := httptest.NewRecorder()
		app.ConfirmEmailChangeHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("Success_Full", func(t *testing.T) {
		token := "full-tok"
		userID := 1
		newEmail := "new@test.com"

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email").WithArgs(token).WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
			AddRow(userID, newEmail, true, false, "old", token))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").WithArgs(userID).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email = \\$1").WithArgs(newEmail, userID).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM email_change_requests").WithArgs(userID).WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectCommit()

		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(userID, "email_change", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req, _ := http.NewRequest("GET", "/confirm-email-change?token="+token, nil)
		rr := httptest.NewRecorder()
		app.ConfirmEmailChangeHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestLoginHandler(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/login", nil)
		rr := httptest.NewRecorder()
		expectBaseQueries(mock, 0)
		app.LoginHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("POST_InvalidCredentials", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
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
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("POST_Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		hash, err := auth.HashPassword("password")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE").WithArgs("test@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "test@example.com", hash, true, false, "", false))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=password"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("POST_UnverifiedBlocked", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		hash, err := auth.HashPassword("password")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}
		// is_email_verified = false → login must be blocked.
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE").WithArgs("test@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "test@example.com", hash, false, false, "", false))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=password"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)

		// Must NOT establish a session/redirect; instead re-render with the banner.
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 (login page with banner), got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "verify-banner") {
			t.Errorf("expected unverified banner in response body")
		}
		if strings.Contains(rr.Header().Get("Set-Cookie"), "user_id") {
			t.Errorf("no authenticated session should be set for unverified user")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestLogoutHandler(t *testing.T) {
	StopStatsTicker()
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	req, err := http.NewRequest("POST", "/logout", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	setSessionUser(t, app, req, 1, false)

	rr := httptest.NewRecorder()
	app.LogoutHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestVerifyEmailHandler(t *testing.T) {
	StopStatsTicker()
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// auth.VerifyEmail uses db.Pool
	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET is_email_verified = TRUE, email_verify_token = NULL WHERE email_verify_token = $1")).
		WithArgs("valid-token").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	req, err := http.NewRequest("GET", "/verify-email?token=valid-token", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	app.VerifyEmailHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestAuthHandlers_TOTP_Detailed(t *testing.T) {
	t.Run("Login_RequireTOTP", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		hashedPassword, err := auth.HashPassword("password")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "user@example.com", hashedPassword, true, true, "SECRET", false))

		form := url.Values{"email": {"user@example.com"}, "password": {"password"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		expectBaseQueries(mock, 0)
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "name=\"totp_code\"") {
			t.Errorf("expected body to contain TOTP input")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Login_VerifyTOTP_Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

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
		expectBaseQueries(mock, 0)
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Login_VerifyTOTP_Failure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

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
		expectBaseQueries(mock, 0)
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Login_VerifyTOTP_TooManyAttempts", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		form := url.Values{"totp_code": {"123456"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.RemoteAddr = "192.0.2.1:1234"
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

		app.Redis.Set(req.Context(), "login_failures:"+app.GetClientIP(req), 5, 0)

		rr := httptest.NewRecorder()
		app.LoginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Too many attempts") {
			t.Errorf("expected too many attempts error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestResendVerificationInlineHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	// auth.ResendVerificationToken uses db.Pool
	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()

	tests := []struct {
		name       string
		method     string
		form       url.Values
		headers    map[string]string
		setupMock  func(mock pgxmock.PgxPoolIface)
		setupRedis func(r db.RedisProvider)
		wantCode   int
		wantJSON   bool
	}{
		{
			name:     "Invalid method",
			method:   http.MethodGet,
			form:     nil,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "Invalid email",
			method:   http.MethodPost,
			form:     url.Values{"email": {"not-an-email"}},
			wantCode: http.StatusOK, // Handler pretends success
			wantJSON: true,
		},
		{
			name:   "IP Rate Limit Exceeded",
			method: http.MethodPost,
			form:   url.Values{"email": {"test@example.com"}},
			setupRedis: func(r db.RedisProvider) {
				r.Set(context.Background(), "resend_limit:192.0.2.1", 5, 0)
			},
			headers:  map[string]string{"X-Forwarded-For": "192.0.2.1"},
			wantCode: http.StatusOK, // Pretends success
		},
		{
			name:   "Email Rate Limit Exceeded",
			method: http.MethodPost,
			form:   url.Values{"email": {"test@example.com"}},
			setupRedis: func(r db.RedisProvider) {
				emailHash := sha256.Sum256([]byte("test@example.com"))
				key := "resend_email_limit:" + hex.EncodeToString(emailHash[:])
				r.Set(context.Background(), key, 3, 0)
			},
			wantCode: http.StatusOK, // Pretends success
		},
		{
			name:   "User Not Found",
			method: http.MethodPost,
			form:   url.Values{"email": {"notfound@example.com"}},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = $1 FOR UPDATE")).
					WithArgs("notfound@example.com").
					WillReturnError(pgx.ErrNoRows)
				mock.ExpectRollback()
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "User Already Verified",
			method: http.MethodPost,
			form:   url.Values{"email": {"verified@example.com"}},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = $1 FOR UPDATE")).
					WithArgs("verified@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
						AddRow(1, true, 0, nil, nil))
				mock.ExpectRollback()
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "Successful Enqueue",
			method: http.MethodPost,
			form:   url.Values{"email": {"test@example.com"}},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = $1 FOR UPDATE")).
					WithArgs("test@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
						AddRow(1, false, 0, nil, nil))
				mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET email_verify_token = $1, verification_resend_count = verification_resend_count + 1, last_verification_resend_at = CURRENT_TIMESTAMP WHERE id = $2")).
					WithArgs(pgxmock.AnyArg(), 1).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectCommit()
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear redis before each test
			app.Redis.FlushAll(context.Background())
			if tt.setupRedis != nil {
				tt.setupRedis(app.Redis)
			}
			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			var req *http.Request
			if tt.form != nil {
				req, _ = http.NewRequest(tt.method, "/resend-verification-inline", strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req, _ = http.NewRequest(tt.method, "/resend-verification-inline", nil)
			}

			// Always request JSON for these tests to easily check status code matching SendResponse logic
			req.Header.Set("X-Requested-With", "XMLHttpRequest")

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			app.ResendVerificationInlineHandler(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("expected code %d, got %d. Body: %s", tt.wantCode, rr.Code, rr.Body.String())
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
