package worker

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// sanitizeEmail validates and sanitizes an email address to prevent
// SMTP header injection (gosec G707). Uses net/mail for proper parsing.
func sanitizeEmail(email string) (string, error) {
	// Strip any CR/LF first
	s := strings.ReplaceAll(email, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	// Validate with net/mail
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("invalid email address %q: %w", s, err)
	}
	return addr.Address, nil
}

// sanitizeHeader removes CR/LF from strings to prevent header injection.
func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

// redactToken safely redacts a token for logging.
func redactToken(token string) string {
	n := 8
	if len(token) < n {
		n = len(token)
	}
	if n == 0 {
		return "<empty>"
	}
	return token[:n] + "..."
}

// redactURL redacts a URL for logging by removing Userinfo, Query, and Path.
func redactURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "[invalid-url]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = "/"
	return parsed.String()
}

// sendMailWithTimeout is a replacement for smtp.SendMail that supports deadlines.
func sendMailWithTimeout(host, port, user, password, from string, to []string, msg []byte) error {
	if len(to) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	cleanFrom, err := sanitizeEmail(from)
	if err != nil {
		return fmt.Errorf("invalid from address: %w", err)
	}

	var cleanTo []string
	for _, t := range to {
		ct, err := sanitizeEmail(t)
		if err != nil {
			return fmt.Errorf("invalid to address %q: %w", t, err)
		}
		cleanTo = append(cleanTo, ct)
	}
	addr := net.JoinHostPort(host, port)
	// #nosec G704 -- Host and port are from controlled environment variables
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial timeout: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	// #nosec G402 -- Remote host is controlled via environment variable
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	defer func() { _ = client.Quit() }()

	// Negotiate STARTTLS if supported (G706 hardening)
	if ok, _ := client.Extension("STARTTLS"); ok {
		config := &tls.Config{
			ServerName: host,
		}
		if err := client.StartTLS(config); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	if user != "" && password != "" {
		auth := smtp.PlainAuth("", user, password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	// #nosec G707 -- Email addresses are sanitized via sanitizeEmail() before use
	if err := client.Mail(cleanFrom); err != nil {
		return err
	}
	for _, addr := range cleanTo {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	return nil
}
