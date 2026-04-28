package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
)

type MockMailer struct {
	SentEmails []struct {
		To      string
		Subject string
		Body    string
	}
}

func (m *MockMailer) SendEmail(to, subject, body string) error {
	m.SentEmails = append(m.SentEmails, struct {
		To      string
		Subject string
		Body    string
	}{to, subject, body})
	return nil
}

func setupTestApp(t *testing.T, mock pgxmock.PgxPoolIface) *App {
	t.Helper()
	// Locate the templates/ directory without using os.Chdir so parallel tests
	// are safe. findTemplatesDir (from template_funcs.go) walks the filesystem.
	if dir := findTemplatesDir(); dir == "" {
		t.Fatalf("could not find templates directory")
	}

	app := NewApp(mock, nil, sessions.NewCookieStore([]byte("test-secret")), &MockMailer{})
	app.InitTemplatesWithFuncs()

	return app
}

func setSessionUser(t *testing.T, app *App, r *http.Request, userID int) {
	session, _ := app.SessionStore.Get(r, "vulfixx-session")
	session.Values["user_id"] = userID
	session.Values["is_admin"] = false
	rr := httptest.NewRecorder()
	err := session.Save(r, rr)
	if err != nil {
		t.Fatalf("failed to save session: %v", err)
	}
	for _, cookie := range rr.Result().Cookies() {
		r.AddCookie(cookie)
	}
}
