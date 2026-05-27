package web

import (
	"testing"
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
