package web

import (
	"context"
	"cve-tracker/internal/db"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v5"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

func TestRateLimitSubject(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.0.2.10", "192.0.2.10"},
		{"::ffff:192.0.2.10", "192.0.2.10"},
		{"2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:bbbb:cccc:dddd:eeee", "2001:db8:1:2::/64"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		if got := rateLimitSubject(tt.in); got != tt.want {
			t.Errorf("rateLimitSubject(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func postLogin(app *App, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	app.LoginHandler(rr, req)
	return rr
}

func TestLogin_PerAccountLockout(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()
	app := setupTestApp(t, mock)

	// The account budget is shared across all client addresses and keyed by the
	// normalized email, so case variations hit the same counter.
	app.Redis.Set(context.Background(), loginAccountFailureKey("victim@example.com"), loginAccountMaxFailures, time.Minute)

	rr := postLogin(app, url.Values{"email": {"Victim@Example.com"}, "password": {"password123"}}, nil)
	if !strings.Contains(rr.Body.String(), "Too many attempts") {
		t.Errorf("expected per-account lockout, got body without error")
	}
	// No password check (DB query) must happen while locked.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

func TestLogin_FailureIncrementsIPAndAccountCounters(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	oldPool := db.Pool
	db.Pool = mock
	defer func() { db.Pool = oldPool }()
	app := setupTestApp(t, mock)

	mock.ExpectQuery("SELECT id, email, password_hash").
		WithArgs("user@example.com").
		WillReturnError(errors.New("no rows"))

	rr := postLogin(app, url.Values{"email": {"user@example.com"}, "password": {"wrongpass"}}, nil)
	if !strings.Contains(rr.Body.String(), "Invalid credentials") {
		t.Fatalf("expected invalid credentials")
	}
	ctx := context.Background()
	if n, _ := app.Redis.Get(ctx, "login_failures:192.0.2.1").Int(); n != 1 {
		t.Errorf("expected IP counter 1, got %d", n)
	}
	if n, _ := app.Redis.Get(ctx, loginAccountFailureKey("user@example.com")).Int(); n != 1 {
		t.Errorf("expected account counter 1, got %d", n)
	}
}

func TestLogin_FailsClosedWhenRedisUnavailable(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)
	app.Redis = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 200 * time.Millisecond})

	rr := postLogin(app, url.Values{"email": {"user@example.com"}, "password": {"password123"}}, nil)
	if !strings.Contains(rr.Body.String(), "temporarily unavailable") {
		t.Errorf("expected fail-closed message when Redis is down")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

func preAuthCookies(t *testing.T, app *App, attempts int) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest("POST", "/login", nil)
	session, _ := app.SessionStore.Get(req, "vulfixx-session")
	session.Values["pre_auth_user_id"] = 1
	session.Values["pre_auth_ts"] = time.Now().Unix()
	session.Values["pre_auth_attempts"] = attempts
	rr := httptest.NewRecorder()
	if err := session.Save(req, rr); err != nil {
		t.Fatalf("session.Save: %v", err)
	}
	return rr.Result().Cookies()
}

func TestLogin_PreAuthClearedAfterMaxTOTPAttempts(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)
	secret := "JBSWY3DPEHPK3PXP"

	mock.ExpectQuery("SELECT is_totp_enabled, COALESCE\\(totp_secret, ''\\) FROM users WHERE id = \\$1").
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"is_totp_enabled", "totp_secret"}).AddRow(true, secret))

	rr := postLogin(app, url.Values{"totp_code": {"000000"}}, preAuthCookies(t, app, preAuthMaxAttempts-1))
	if !strings.Contains(rr.Body.String(), "Please sign in again") {
		t.Fatalf("expected pre-auth to be cleared after max attempts")
	}

	// The returned session must no longer carry the pre-auth marker.
	req := httptest.NewRequest("GET", "/login", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	session, _ := app.SessionStore.Get(req, "vulfixx-session")
	if _, ok := session.Values["pre_auth_user_id"]; ok {
		t.Errorf("pre_auth_user_id should have been removed from the session")
	}
	if n, _ := app.Redis.Get(context.Background(), totpAccountFailureKey(1)).Int(); n != 1 {
		t.Errorf("expected per-account TOTP failure counter 1, got %d", n)
	}
}

func TestLogin_TOTPAccountLockout(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)
	app.Redis.Set(context.Background(), totpAccountFailureKey(1), totpAccountMaxFailures, time.Minute)

	rr := postLogin(app, url.Values{"totp_code": {"123456"}}, preAuthCookies(t, app, 0))
	if !strings.Contains(rr.Body.String(), "Too many attempts") {
		t.Errorf("expected per-account TOTP lockout")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

func TestConsumeTOTP_RejectsReplay(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	app.Now = func() time.Time { return now }
	secret := "JBSWY3DPEHPK3PXP"
	ctx := context.Background()

	code, _ := totp.GenerateCode(secret, now)
	if ok, err := app.consumeTOTP(ctx, 7, code, secret); !ok || err != nil {
		t.Fatalf("first use should succeed: ok=%v err=%v", ok, err)
	}
	if ok, _ := app.consumeTOTP(ctx, 7, code, secret); ok {
		t.Errorf("replayed code must be rejected")
	}
	// An older (but still in-skew) code is rejected too.
	prev, _ := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if ok, _ := app.consumeTOTP(ctx, 7, prev, secret); ok {
		t.Errorf("older code must be rejected after a newer one was used")
	}
	// Other users are unaffected.
	if ok, _ := app.consumeTOTP(ctx, 8, code, secret); !ok {
		t.Errorf("same code for another user should be accepted")
	}
	if ok, _ := app.consumeTOTP(ctx, 9, "000000", secret); ok && code != "000000" {
		t.Errorf("wrong code must be rejected")
	}
}

func TestRevokeUserSessions(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)
	ctx := context.Background()

	for i, sid := range []string{"a", "b", "c"} {
		app.Redis.Set(ctx, "vulfixx_session:"+sid, "data", time.Hour)
		app.Redis.ZAdd(ctx, "user_sessions:5", redis.Z{Score: float64(i), Member: sid})
	}

	app.RevokeUserSessions(ctx, 5, "b")

	for sid, want := range map[string]int64{"a": 0, "b": 1, "c": 0} {
		if n, _ := app.Redis.Exists(ctx, "vulfixx_session:"+sid).Result(); n != want {
			t.Errorf("session %s exists=%d, want %d", sid, n, want)
		}
	}
	if members, _ := app.Redis.ZRange(ctx, "user_sessions:5", 0, -1).Result(); len(members) != 1 || members[0] != "b" {
		t.Errorf("expected only the kept session to stay tracked, got %v", members)
	}

	app.untrackSession(ctx, 5, "b")
	if n, _ := app.Redis.ZCard(ctx, "user_sessions:5").Result(); n != 0 {
		t.Errorf("expected session to be untracked, %d remain", n)
	}
}
