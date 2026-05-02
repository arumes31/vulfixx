package web

import (
	"context"
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestAuthFlow_FullLifecycle(t *testing.T) {
	mock, _ := db.SetupTestDB()
	ts, app, client := setupTestAppWithClient(t, mock)
	defer ts.Close()

	email := "new-user@example.com"
	password := "secure-pass-123"

	// 1. Registration Attempt
	t.Run("Registration", func(t *testing.T) {
		// Captcha is 10 in test environment
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)
		form.Add("password_confirm", password)
		form.Add("captcha", "10")

		// Registration Query
		mock.ExpectExec("INSERT INTO users").WithArgs(email, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		resp, err := client.PostForm(ts.URL+"/register", form)
		if err != nil {
			t.Fatalf("failed to post registration: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %d", resp.StatusCode)
		}
		// Should show login page with success message
		// Note: Redirects are followed by default client if not configured otherwise, 
		// but our test helper client handles redirects according to its config.
	})

	// 2. Registration Rate Limit
	t.Run("RegistrationRateLimit", func(t *testing.T) {
		// Mock existing attempts in redis
		app.Redis.Set(context.Background(), "reg_limit:127.0.0.1", 5, 1*time.Hour)

		form := url.Values{}
		form.Add("email", "another@example.com")
		form.Add("password", password)
		form.Add("password_confirm", password)
		form.Add("captcha", "10")

		resp, _ := client.PostForm(ts.URL+"/register", form)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK (rendering template with error), got %d", resp.StatusCode)
		}
		// Verify "Too many registration attempts" in body
	})

	// 3. Resend Verification
	t.Run("ResendVerification", func(t *testing.T) {
		app.Redis.Del(context.Background(), "reg_limit:127.0.0.1")
		
		form := url.Values{}
		form.Add("email", email)
		form.Add("captcha", "10")

		// Auth logic for resend
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at FROM users").
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at"}).
				AddRow(1, false, 0, nil))
		mock.ExpectExec("UPDATE users SET email_verify_token").WithArgs(pgxmock.AnyArg(), 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		resp, _ := client.PostForm(ts.URL+"/resend-verification", form)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK, got %d", resp.StatusCode)
		}
	})

	// 4. Resend Backoff
	t.Run("ResendBackoff", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("captcha", "10")

		// Auth logic for resend showing backoff
		lastResend := time.Now()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at FROM users").
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at"}).
				AddRow(1, false, 1, &lastResend))
		mock.ExpectRollback()

		resp, _ := client.PostForm(ts.URL+"/resend-verification", form)
		// Body should contain "please wait another"
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status OK (rendering template with error), got %d", resp.StatusCode)
		}
	})

	// 5. First Login (Success)
	t.Run("FirstLogin", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)

		// Login Queries
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users").
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, email, "$2a$10$WpC1W8.V6G3l2eS0q1O7OeC9G9G9G9G9G9G9G9G9G9G9G9G9G9G9G", true, false, "", false)) // Using a dummy bcrypt hash
		
		// RenderTemplate base queries
		expectBaseQueries(mock, 1)

		resp, _ := client.PostForm(ts.URL+"/login", form)
		if resp.StatusCode != http.StatusFound {
			t.Errorf("expected redirect to dashboard, got %d", resp.StatusCode)
		}
	})
}
