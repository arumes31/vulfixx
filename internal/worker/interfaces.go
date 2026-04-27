package worker

import (
	"fmt"
	"net/http"
	"os"
)

// EmailSender defines the interface for sending emails.
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

// HTTPClient defines the interface for making HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Default implementation for EmailSender
type realEmailSender struct{}

func (s *realEmailSender) SendEmail(toEmail, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if host == "" || from == "" {
		return fmt.Errorf("SMTP configuration missing")
	}

	// Validate subject, email, and from address to prevent header injection
	cleanSubject := sanitizeHeader(subject)
	cleanTo, err := sanitizeEmail(toEmail)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	cleanFrom, err := sanitizeEmail(from)
	if err != nil {
		return fmt.Errorf("invalid sender (SMTP_FROM): %w", err)
	}

	msg := []byte("To: " + cleanTo + "\r\n" + "From: " + cleanFrom + "\r\n" + "Subject: " + cleanSubject + "\r\n" + "Content-Type: text/html; charset=UTF-8\r\n" + "\r\n" + body)
	return sendMailWithTimeout(host, port, user, password, cleanFrom, []string{cleanTo}, msg)
}

var (
	// GlobalEmailSender is the instance used by the worker.
	GlobalEmailSender EmailSender = &realEmailSender{}

	// GlobalHTTPClient is the instance used by the worker for outgoing requests.
	GlobalHTTPClient HTTPClient = &http.Client{
		Transport: &http.Transport{
			// Basic security for outgoing requests
		},
	}
)
