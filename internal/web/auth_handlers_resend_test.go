package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cve-tracker/internal/db"
	"github.com/pashagolub/pgxmock/v3"
)

func TestResendVerificationInlineHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()

	app := setupTestApp(t, mock)

	tests := []struct {
		name       string
		method     string
		body       string
		contentType string
		email      string
		setupMock  func()
		setupRedis func()
		setupAsynq bool
		wantMsg    string
	}{
		{
			name:   "Method not allowed",
			method: http.MethodGet,
			wantMsg: "Method not allowed",
		},
		{
			name:   "Invalid form data",
			method: http.MethodPost,
			body:   ";invalid-form-data;",
			contentType: "application/x-www-form-urlencoded; boundary=;",
			wantMsg: "Invalid form",
		},
		{
			name:   "Invalid email",
			method: http.MethodPost,
			email:  "invalid-email",
			wantMsg: "If this email is registered and unverified",
		},
		{
			name:   "Valid email - success with Redis Queue",
			method: http.MethodPost,
			email:  "test@example.com",
			setupMock: func() {
				mock.ExpectBegin()
				rows := pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
					AddRow(1, false, 0, time.Now().Add(-1*time.Hour), "old-token")
				mock.ExpectQuery(`SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = \$1 FOR UPDATE`).
					WithArgs("test@example.com").
					WillReturnRows(rows)
				mock.ExpectExec(`UPDATE users SET email_verify_token = \$1, verification_resend_count = verification_resend_count \+ 1, last_verification_resend_at = CURRENT_TIMESTAMP WHERE id = \$2`).
					WithArgs(pgxmock.AnyArg(), 1).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectCommit()
			},
			wantMsg: "If this email is registered and unverified",
		},
		{
			name:   "Valid email - success with Asynq Client",
			method: http.MethodPost,
			email:  "asynq@example.com",
			setupAsynq: true,
			setupMock: func() {
				mock.ExpectBegin()
				rows := pgxmock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
					AddRow(1, false, 0, time.Now().Add(-1*time.Hour), "old-token")
				mock.ExpectQuery(`SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = \$1 FOR UPDATE`).
					WithArgs("asynq@example.com").
					WillReturnRows(rows)
				mock.ExpectExec(`UPDATE users SET email_verify_token = \$1, verification_resend_count = verification_resend_count \+ 1, last_verification_resend_at = CURRENT_TIMESTAMP WHERE id = \$2`).
					WithArgs(pgxmock.AnyArg(), 1).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
				mock.ExpectCommit()
			},
			wantMsg: "If this email is registered and unverified",
		},
		{
			name:   "Valid email - auth failure",
			method: http.MethodPost,
			email:  "fail@example.com",
			setupMock: func() {
				mock.ExpectBegin()
				mock.ExpectQuery(`SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = \$1 FOR UPDATE`).
					WithArgs("fail@example.com").
					WillReturnError(errors.New("db error"))
				mock.ExpectRollback()
			},
			wantMsg: "If this email is registered and unverified",
		},
		{
			name:   "IP Rate limited",
			method: http.MethodPost,
			email:  "test2@example.com",
			setupRedis: func() {
				app.Redis.Set(context.Background(), "resend_limit:192.0.2.1", 5, 1*time.Hour)
			},
			wantMsg: "If this email is registered and unverified",
		},
		{
			name:   "Email Rate limited",
			method: http.MethodPost,
			email:  "test3@example.com",
			setupRedis: func() {
				emailHash := sha256.Sum256([]byte("test3@example.com"))
				emailRlKey := "resend_email_limit:" + hex.EncodeToString(emailHash[:])
				app.Redis.Set(context.Background(), emailRlKey, 3, 30*time.Minute)
			},
			wantMsg: "If this email is registered and unverified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app.Redis.FlushDB(context.Background())

			oldAsynq := app.AsynqClient
			if tt.setupAsynq {
			    // Handled inside auth handlers
			}
			defer func() { app.AsynqClient = oldAsynq }()

			if tt.setupMock != nil {
				tt.setupMock()
			}
			if tt.setupRedis != nil {
				tt.setupRedis()
			}

			var req *http.Request
			if tt.body != "" {
			    req = httptest.NewRequest(tt.method, "/auth/resend-verification-inline", strings.NewReader(tt.body))
			    req.Header.Add("Content-Type", tt.contentType)
			} else if tt.method == http.MethodPost {
				form := url.Values{}
				if tt.email != "" {
				    form.Add("email", tt.email)
				}
				req = httptest.NewRequest(tt.method, "/auth/resend-verification-inline", strings.NewReader(form.Encode()))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, "/auth/resend-verification-inline", nil)
			}
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			req.RemoteAddr = "192.0.2.1:1234"

			w := httptest.NewRecorder()
			app.ResendVerificationInlineHandler(w, req)

			if tt.setupMock != nil {
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("there were unfulfilled expectations: %s", err)
				}
			}

			if !strings.Contains(w.Body.String(), tt.wantMsg) {
				t.Errorf("expected response to contain %q, got %q", tt.wantMsg, w.Body.String())
			}
		})
	}
}
