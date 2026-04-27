package web

import (
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
	found := false
	for i := 0; i < 4; i++ {
		if _, err := os.Stat("templates"); err == nil {
			found = true
			break
		}
		_ = os.Chdir("..")
	}
	if !found {
		_ = os.Chdir(origWD)
		t.Fatalf("could not find templates directory from %s", origWD)
	}

	app := NewApp(mock, nil, sessions.NewCookieStore([]byte("test-secret")), &MockMailer{})
	app.InitTemplatesWithFuncs()

	// Restore working directory
	_ = os.Chdir(origWD)
	
	return app
}
