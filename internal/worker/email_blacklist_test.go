package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestIsEmailDomainBlacklisted(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"test@gmail.com", false},
		{"user@vulfixx.org", false},
		{"bad@mailinator.com", true},
		{"malicious@trashmail.com", true},
		{"attacker@sub.10minutemail.com", true},
		{"invalid-email", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			res := isEmailDomainBlacklisted(tt.email)
			if res != tt.expected {
				t.Errorf("expected isEmailDomainBlacklisted(%q) to be %v, got %v", tt.email, tt.expected, res)
			}
		})
	}
}

func TestIsEmailDomainBlacklisted_CustomEnv(t *testing.T) {
	t.Setenv("EMAIL_DOMAIN_BLACKLIST", "malicious.com,evil.org")

	tests := []struct {
		email    string
		expected bool
	}{
		{"test@gmail.com", false},
		{"attacker@malicious.com", true},
		{"user@evil.org", true},
		{"sub@evil.org", true},
		{"bad@mailinator.com", false}, // Overridden by env
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			res := isEmailDomainBlacklisted(tt.email)
			if res != tt.expected {
				t.Errorf("expected isEmailDomainBlacklisted(%q) to be %v, got %v", tt.email, tt.expected, res)
			}
		})
	}
}

func TestEmailWorker_BlacklistBlocking(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	mockMailer := &EmailSenderMockBlacklist{}
	w := &Worker{
		Redis:  rdb,
		Mailer: mockMailer,
	}

	// 1. Verification email verification blocked
	payload1, err := json.Marshal(map[string]string{"email": "spam@mailinator.com", "token": "tok123"})
	if err != nil {
		t.Fatalf("failed to marshal payload1: %v", err)
	}
	if err := rdb.LPush(context.Background(), "email_verification_queue", payload1).Err(); err != nil {
		t.Fatalf("failed to push payload1 to redis: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel1()
	w.processEmailVerification(ctx1)

	if mockMailer.Count > 0 {
		t.Errorf("expected no verification emails to be sent, but sent %d", mockMailer.Count)
	}

	// Reset mailer count
	mockMailer.Count = 0

	// 2. Email change email blocked
	payload2, err := json.Marshal(map[string]string{"email": "spam@mailinator.com", "token": "tok456", "type": "new"})
	if err != nil {
		t.Fatalf("failed to marshal payload2: %v", err)
	}
	if err := rdb.LPush(context.Background(), "email_change_queue", payload2).Err(); err != nil {
		t.Fatalf("failed to push payload2 to redis: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	w.processEmailChange(ctx2)

	if mockMailer.Count > 0 {
		t.Errorf("expected no email change notification emails to be sent, but sent %d", mockMailer.Count)
	}
}

type EmailSenderMockBlacklist struct {
	Count int
	Err   error
}

func (m *EmailSenderMockBlacklist) SendEmail(to, subject, body string) error {
	if m.Err != nil {
		return m.Err
	}
	m.Count++
	return nil
}
