package web

import (
	"net/http"
	"net/http/httptest"
	"os"
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
	// Ensure we can find templates/ directory
	origWD, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWD) }()

	found := false
	for i := 0; i < 5; i++ {
		if _, err := os.Stat("templates"); err == nil {
			found = true
			break
		}
		if err := os.Chdir(".."); err != nil {
			break
		}
	}

	if !found {
		t.Fatalf("could not find templates directory from %s", origWD)
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
