package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"cve-tracker/internal/db"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestResendVerificationInlineHandler(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	app.Redis = redis.NewClient(&redis.Options{Addr: mr.Addr()})

	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()

	tests := []struct {
		name       string
		method     string
		formValues map[string]string
		setupRedis func()
		wantBody   string // optional substring match
	}{
		{
			name:       "Method Not Allowed",
			method:     http.MethodGet,
			formValues: nil,
			wantBody:   "Method not allowed",
		},
		{
			name:   "Invalid Email",
			method: http.MethodPost,
			formValues: map[string]string{
				"email": "invalid",
			},
			wantBody: "If this email is registered and unverified, a new verification link has been sent.",
		},
		{
			name:   "Per-IP Rate Limit Exceeded",
			method: http.MethodPost,
			formValues: map[string]string{
				"email": "test@example.com",
			},
			setupRedis: func() {
				_ = mr.Set("resend_limit:127.0.0.1", "5")
			},
			wantBody: "If this email is registered and unverified, a new verification link has been sent.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr.FlushAll()
			if tt.setupRedis != nil {
				tt.setupRedis()
			}

			var req *http.Request
			if tt.method == http.MethodPost && tt.formValues != nil {
				form := url.Values{}
				for k, v := range tt.formValues {
					form.Set(k, v)
				}
				req = httptest.NewRequest(tt.method, "/resend", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			} else {
				req = httptest.NewRequest(tt.method, "/resend", nil)
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}

			req.RemoteAddr = "127.0.0.1:1234"

			rr := httptest.NewRecorder()
			app.ResendVerificationInlineHandler(rr, req)

			if tt.wantBody != "" {
				if !strings.Contains(rr.Body.String(), tt.wantBody) {
					t.Errorf("expected body to contain %q, got %q", tt.wantBody, rr.Body.String())
				}
			}
		})
	}
}
