package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	ctx := context.Background()

	tests := []struct {
		name       string
		method     string
		email      string
		remoteAddr string
		setupRedis func()
		setupMock  func()
		wantStatus int
		wantBody   string
	}{
		{
			name:       "MethodNotAllowed",
			method:     http.MethodGet,
			email:      "",
			remoteAddr: "192.0.2.1:1234",
			setupRedis: func() {},
			setupMock:  func() {},
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method not allowed",
		},
		{
			name:       "InvalidEmail",
			method:     http.MethodPost,
			email:      "invalid-email",
			remoteAddr: "192.0.2.1:1234",
			setupRedis: func() {},
			setupMock:  func() {},
			wantStatus: http.StatusOK,
			wantBody:   "sent",
		},
		{
			name:       "RateLimitIP",
			method:     http.MethodPost,
			email:      "valid@example.com",
			remoteAddr: "192.0.2.1:1234",
			setupRedis: func() {
				app.Redis.Set(ctx, "resend_limit:192.0.2.1", 5, 0)
			},
			setupMock:  func() {},
			wantStatus: http.StatusOK,
			wantBody:   "sent",
		},
		{
			name:       "RateLimitEmail",
			method:     http.MethodPost,
			email:      "limited@example.com",
			remoteAddr: "192.0.2.2:1234",
			setupRedis: func() {
				app.Redis.FlushAll(ctx)
				emailHash := sha256.Sum256([]byte("limited@example.com"))
				emailRlKey := "resend_email_limit:" + hex.EncodeToString(emailHash[:])
				app.Redis.Set(ctx, emailRlKey, 3, 0)
			},
			setupMock:  func() {},
			wantStatus: http.StatusOK,
			wantBody:   "sent",
		},
		{
			name:       "Success",
			method:     http.MethodPost,
			email:      "success@example.com",
			remoteAddr: "192.0.2.3:1234",
			setupRedis: func() {
				app.Redis.FlushAll(ctx)
			},
			setupMock: func() {
				mock.ExpectQuery(`SELECT u\.id, t\.token, COALESCE\(t\.last_resend, '1970-01-01'\) FROM users u LEFT JOIN verification_tokens t`).
					WithArgs("success@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "token", "last_resend"}).
						AddRow("uuid-123", nil, time.Time{}))

				mock.ExpectExec(`INSERT INTO verification_tokens`).
					WithArgs("uuid-123", pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			wantStatus: http.StatusOK,
			wantBody:   "sent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupRedis()
			tt.setupMock()

			var req *http.Request
			if tt.method == http.MethodPost {
				form := url.Values{}
				if tt.email != "" {
					form.Add("email", tt.email)
				}
				req = httptest.NewRequest(tt.method, "/resend-inline", strings.NewReader(form.Encode()))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, "/resend-inline", nil)
			}
			req.Header.Add("X-Requested-With", "XMLHttpRequest")
			req.RemoteAddr = tt.remoteAddr

			w := httptest.NewRecorder()
			app.ResendVerificationInlineHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("ResendVerificationInlineHandler() status = %d, want %d", w.Code, tt.wantStatus)
			}
			if !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Errorf("ResendVerificationInlineHandler() body %q, want substring %q", w.Body.String(), tt.wantBody)
			}
		})
	}
}
