package web

import (
	"context"
	"cve-tracker/internal/db"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthFlow_FullLifecycle(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	mock.MatchExpectationsInOrder(false)
	
	oldPool := db.Pool
	db.Pool = mock
	t.Cleanup(func() {
		db.Pool = oldPool
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	ts, app, client := setupTestServer(t, mock)

	// Add the new routes to the test server specifically for this test
	mux := http.NewServeMux()
	mux.HandleFunc("/register", app.RegisterHandler)
	mux.HandleFunc("/login", app.LoginHandler)
	mux.HandleFunc("/resend-verification", app.ResendVerificationHandler)
	mux.HandleFunc("/verify-email", app.VerifyEmailHandler)
	mux.HandleFunc("/captcha", app.CaptchaHandler)
	mux.Handle("/dashboard", app.AuthMiddleware(http.HandlerFunc(app.DashboardHandler)))
	ts.Config.Handler = mux

	email := "new-user@example.com"
	password := "secure-pass-123"

	// 1. Registration Attempt
	t.Run("Registration", func(t *testing.T) {
		// Call captcha to set session
		respCap, err := client.Get(ts.URL + "/captcha")
		if err != nil {
			t.Fatalf("failed to get captcha: %v", err)
		}
		respCap.Body.Close()

		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)
		form.Add("password_confirm", password)
		form.Add("captcha", "10") // CaptchaHandler in test returns 5+5=10

		mock.ExpectExec("INSERT INTO users").WithArgs(email, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		resp, err := client.PostForm(ts.URL+"/register", form)
		if err != nil {
			t.Fatalf("failed to post registration: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %d", resp.StatusCode)
		}
	})

	// 2. Registration Rate Limit
	t.Run("RegistrationRateLimit", func(t *testing.T) {
		// Refresh captcha
		respCap, err := client.Get(ts.URL + "/captcha")
		if err != nil {
			t.Fatalf("failed to get captcha: %v", err)
		}
		respCap.Body.Close()

		if err := app.Redis.Set(context.Background(), "reg_limit:127.0.0.1", 5, 1*time.Hour).Err(); err != nil {
			t.Fatalf("failed to set redis reg_limit: %v", err)
		}

		form := url.Values{}
		form.Add("email", "another@example.com")
		form.Add("password", password)
		form.Add("password_confirm", password)
		form.Add("captcha", "10")

		resp, err := client.PostForm(ts.URL+"/register", form)
		if err != nil {
			t.Fatalf("failed to post registration: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK (rendering template with error), got %d", resp.StatusCode)
		}
	})

	// 3. Resend Verification
	t.Run("ResendVerification", func(t *testing.T) {
		app.Redis.Del(context.Background(), "reg_limit:127.0.0.1")
		
		// Refresh captcha
		respCap, err := client.Get(ts.URL + "/captcha")
		if err != nil {
			t.Fatalf("failed to get captcha: %v", err)
		}
		respCap.Body.Close()

		form := url.Values{}
		form.Add("email", email)
		form.Add("captcha", "10")

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users").
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, false, 0, nil, nil))
		mock.ExpectExec("UPDATE users SET email_verify_token").WithArgs(pgxmock.AnyArg(), 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		resp, err := client.PostForm(ts.URL+"/resend-verification", form)
		if err != nil {
			t.Fatalf("failed to post resend: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %d", resp.StatusCode)
		}
	})

	// 4. Resend Backoff
	t.Run("ResendBackoff", func(t *testing.T) {
		// Refresh captcha
		respCap, err := client.Get(ts.URL + "/captcha")
		if err != nil {
			t.Fatalf("failed to get captcha: %v", err)
		}
		respCap.Body.Close()

		form := url.Values{}
		form.Add("email", email)
		form.Add("captcha", "10")

		lastResend := time.Now()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users").
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, false, 1, &lastResend, nil))
		mock.ExpectRollback()

		resp, err := client.PostForm(ts.URL+"/resend-verification", form)
		if err != nil {
			t.Fatalf("failed to post resend: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %d", resp.StatusCode)
		}
	})

	// 5. First Login (Success)
	t.Run("FirstLogin", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users").
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, email, string(hash), true, false, "", false))
		
		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(1, "login", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		resp, err := client.PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatalf("failed to post login: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("expected redirect to dashboard, got %d", resp.StatusCode)
		}
	})
}
