package worker

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// EmailSender defines the interface for sending emails.
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

// HTTPClient defines the interface for making HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Ticker defines a mockable interface for time.Ticker.
type Ticker interface {
	Chan() <-chan time.Time
	Stop()
}

// realTicker wraps time.Ticker.
type realTicker struct {
	*time.Ticker
}

func (rt *realTicker) Chan() <-chan time.Time {
	return rt.C
}

// Timer defines a mockable interface for time.Timer.
type Timer interface {
	Chan() <-chan time.Time
	Stop() bool
}

// realTimer wraps time.Timer.
type realTimer struct {
	*time.Timer
}

func (rt *realTimer) Chan() <-chan time.Time {
	return rt.C
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
		err := fmt.Errorf("SMTP configuration missing (host, port, and from are required)")
		log.Printf("Worker: %v", err)
		return err
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
