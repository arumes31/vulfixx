package worker

import (
	"fmt"
	"net/http"
)

// EmailSender defines the interface for sending emails.
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

// HTTPClient defines the interface for making HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// RealEmailSender is the default implementation for EmailSender
type RealEmailSender struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
}

func NewEmailSender(host, port, user, password, from string) EmailSender {
	return &RealEmailSender{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		From:     from,
	}
}

func (s *RealEmailSender) SendEmail(toEmail, subject, body string) error {
	if s.Host == "" || s.From == "" || s.Port == "" {
		return fmt.Errorf("SMTP configuration missing (host, port, and from are required)")
	}

	// Validate subject, email, and from address to prevent header injection
	cleanSubject := sanitizeHeader(subject)
	cleanTo, err := sanitizeEmail(toEmail)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	cleanFrom, err := sanitizeEmail(s.From)
	if err != nil {
		return fmt.Errorf("invalid sender (SMTP_FROM): %w", err)
	}

	msg := []byte("To: " + cleanTo + "\r\n" + "From: " + cleanFrom + "\r\n" + "Subject: " + cleanSubject + "\r\n" + "Content-Type: text/html; charset=UTF-8\r\n" + "\r\n" + body)
	return sendMailWithTimeout(s.Host, s.Port, s.User, s.Password, cleanFrom, []string{cleanTo}, msg)
}
