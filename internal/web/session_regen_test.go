package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"

	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
)

// regenerateSession must both rotate the identifier and leave the session usable.
// The bug this guards against restored neither: it expired the session and then handed
// the same object back, so the next Save emitted a second deletion cookie.
func TestRegenerateSession(t *testing.T) {
	store := sessions.NewCookieStore([]byte("test-key-32-bytes-long-000000000"))
	store.Options = &sessions.Options{Path: "/", MaxAge: sessionMaxAge}

	r := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()

	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	session.ID = "pre-auth-session-id"
	session.Values["pre_auth_user_id"] = 42

	if err := regenerateSession(r, w, session); err != nil {
		t.Fatalf("regenerateSession: %v", err)
	}

	if session.ID == "pre-auth-session-id" {
		t.Error("session ID was not rotated — a planted pre-auth ID would survive login")
	}
	if session.Options.MaxAge != sessionMaxAge {
		t.Errorf("MaxAge = %d, want %d; a negative or zero value means no cookie is issued",
			session.Options.MaxAge, sessionMaxAge)
	}
	if len(session.Values) != 0 {
		t.Errorf("pre-auth values survived regeneration: %v", session.Values)
	}
}

// End to end through the handler: a successful login must leave the client holding a
// real session cookie. The regression emitted two deletion cookies and no session, so
// every login redirected to /dashboard and bounced straight back to /login.
func TestLoginHandlerIssuesSessionCookie(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	const email = "session-regen@example.com"
	const password = "correct-horse-battery-staple"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users").
		WithArgs(email).
		WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
			AddRow(1, email, hash, true, false, "", false))
	mock.ExpectExec("INSERT INTO user_activity_logs").
		WithArgs(1, "login", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	app.LoginHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 to /dashboard, got %d", rr.Code)
	}

	// Walk every Set-Cookie for the session and keep the last, which is what a browser
	// applies. The bug produced only deletion cookies, so there was no survivor.
	var final *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "vulfixx-session" {
			final = c
		}
	}
	if final == nil {
		t.Fatal("no vulfixx-session cookie was set at all")
	}
	if final.Value == "" {
		t.Error("session cookie has an empty value — the client would be logged out immediately")
	}
	if final.MaxAge < 0 {
		t.Errorf("session cookie carries MaxAge=%d, which deletes it; login would not stick", final.MaxAge)
	}
}
