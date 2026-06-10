package web

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestMockMailer_SendEmail(t *testing.T) {
	tests := []struct {
		name    string
		to      string
		subject string
		body    string
	}{
		{
			name:    "Send one email",
			to:      "test@example.com",
			subject: "Test Subject",
			body:    "Test Body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockMailer{}
			err := m.SendEmail(tt.to, tt.subject, tt.body)
			if err != nil {
				t.Fatalf("SendEmail() error = %v", err)
			}

			if len(m.SentEmails) != 1 {
				t.Fatalf("Expected 1 email sent, got %d", len(m.SentEmails))
			}

			sent := m.SentEmails[0]
			if sent.To != tt.to {
				t.Errorf("Sent email To = %v, want %v", sent.To, tt.to)
			}
			if sent.Subject != tt.subject {
				t.Errorf("Sent email Subject = %v, want %v", sent.Subject, tt.subject)
			}
			if sent.Body != tt.body {
				t.Errorf("Sent email Body = %v, want %v", sent.Body, tt.body)
			}
		})
	}
}

func TestMockMailer(t *testing.T) {
	mailer := &MockMailer{}
	err := mailer.SendEmail("test@example.com", "Subject", "Body")
	if err != nil {
		t.Fatalf("SendEmail failed: %v", err)
	}
	if len(mailer.SentEmails) != 1 {
		t.Errorf("expected 1 email, got %d", len(mailer.SentEmails))
	}
	if mailer.SentEmails[0].To != "test@example.com" {
		t.Errorf("expected to test@example.com, got %s", mailer.SentEmails[0].To)
	}
}

func TestSetupTestApp(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	if app == nil {
		t.Fatal("expected app to be non-nil")
	}
	if app.Pool != mock {
		t.Error("app.Pool not set to mock")
	}
	if app.Redis == nil {
		t.Error("app.Redis not set")
	}
}

func TestSetSessionUser(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()
	app := setupTestApp(t, mock)

	req := httptest.NewRequest("GET", "/", nil)
	setSessionUser(t, app, req, 123, true)

	userID, ok := app.GetUserID(req)
	if !ok || userID != 123 {
		t.Errorf("expected user_id 123, got %d (ok: %v)", userID, ok)
	}
	isAdmin := app.IsAdmin(req)
	if !isAdmin {
		t.Error("expected isAdmin to be true")
	}
}

func TestExpectBaseQueries(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	t.Run("Valid User", func(t *testing.T) {
		expectBaseQueries(mock, 123)

		// Onboarding
		var completed bool
		_ = mock.QueryRow(context.Background(), "SELECT onboarding_completed FROM users WHERE id = $1", 123).Scan(&completed)

		// Sub count
		var count int
		_ = mock.QueryRow(context.Background(), "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1", 123).Scan(&count)

		// Team list
		_, _ = mock.Query(context.Background(), "SELECT t.id, t.name, tm.user_id FROM teams t LEFT JOIN team_members tm ON t.id = tm.team_id AND tm.user_id = $1 WHERE tm.user_id = $1 OR t.id = $2", 123, 0)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("not all expectations were met: %v", err)
		}
	})

	t.Run("Invalid User", func(t *testing.T) {
		expectBaseQueries(mock, 0)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("expectations set for invalid user: %v", err)
		}
	})
}

func TestSetupTestServer(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	ts, app, client := setupTestServer(t, mock)
	if ts == nil || app == nil || client == nil {
		t.Fatal("setupTestServer returned nil values")
	}
}
