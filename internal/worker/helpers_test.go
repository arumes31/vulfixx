package worker

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type EmailSenderMock struct {
	Count       int
	LastTo      string
	LastSubject string
	LastBody      string
}

func (m *EmailSenderMock) SendEmail(to, subject, body string) error {
	m.Count++
	m.LastTo = to
	m.LastSubject = subject
	m.LastBody = body
	return nil
}

type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("DoFunc not set")
}

// EmailSenderMockV2 is a thread-safe mock for use with concurrent Asynq workers.
type EmailSenderMockV2 struct {
	count atomic.Int32
	mu    sync.Mutex
	Err   error
}

func (m *EmailSenderMockV2) SendEmail(to, subject, body string) error {
	m.count.Add(1)
	m.mu.Lock()
	err := m.Err
	m.mu.Unlock()
	return err
}

// Count returns the number of emails sent (thread-safe).
func (m *EmailSenderMockV2) Count() int {
	return int(m.count.Load())
}

func TestWorkerHelpers(t *testing.T) {
	t.Run("SanitizeEmail", func(t *testing.T) {
		email, err := sanitizeEmail("test@example.com")
		if err != nil || email != "test@example.com" {
			t.Errorf("sanitizeEmail failed: %v, %s", err, email)
		}
		_, err = sanitizeEmail("test@example.com\r\n")
		if err == nil {
			t.Error("expected error for email with CRLF")
		}
	})

	t.Run("SanitizeHeader", func(t *testing.T) {
		input := "Line 1\r\nLine 2\nLine 3"
		expected := "Line 1Line 2Line 3"
		if got := sanitizeHeader(input); got != expected {
			t.Errorf("sanitizeHeader failed: got %q, want %q", got, expected)
		}
	})

	t.Run("ClassifyVendorAdvisories", func(t *testing.T) {
		refs := []string{
			"https://example.com/advisory/123",
			"https://github.com/advisories/GHSA-123",
		}
		advisories := classifyVendorAdvisories(refs)
		if len(advisories) != 2 {
			t.Errorf("expected 2 advisories, got %d", len(advisories))
		}
	})

	t.Run("SendMailWithTimeout_Errors", func(t *testing.T) {
		err := sendMailWithTimeout("localhost", "25", "user", "pass", "bad-email", []string{"to@example.com"}, []byte("msg"))
		if err == nil {
			t.Error("expected error for invalid from address")
		}

		err = sendMailWithTimeout("localhost", "25", "user", "pass", "to@example.com", []string{"bad-email\r\n"}, []byte("msg"))
		if err == nil {
			t.Error("expected error for invalid to address")
		}

		err = sendMailWithTimeout("localhost", "invalid-port", "user", "pass", "to@example.com", []string{"to@example.com"}, []byte("msg"))
		if err == nil {
			t.Error("expected error for invalid port format")
		}

		err = sendMailWithTimeout("localhost", "0", "user", "pass", "to@example.com", []string{"to@example.com"}, []byte("msg"))
		if err == nil {
			t.Error("expected error for port 0")
		}

		err = sendMailWithTimeout("localhost", "25", "", "", "to@example.com", nil, []byte("msg"))
		if err == nil {
			t.Error("expected error for empty recipients")
		}
	})

	t.Run("SendMailWithTimeout_DialFailure", func(t *testing.T) {
		// Use port 1 which is usually closed/blocked
		err := sendMailWithTimeout("127.0.0.1", "1", "", "", "from@example.com", []string{"to@example.com"}, []byte("msg"))
		if err == nil {
			t.Error("expected error for connection failure to closed port")
		}
	})

	t.Run("SendMailWithTimeout_SuccessPlaintext", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer lis.Close()

		host, port, _ := net.SplitHostPort(lis.Addr().String())

		errChan := make(chan error, 1)
		go func() {
			conn, err := lis.Accept()
			if err != nil {
				errChan <- err
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			// 1. Greeting
			_, _ = conn.Write([]byte("220 localhost ESMTP\r\n"))

			// 2. Read EHLO
			n, err := conn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "EHLO") {
				errChan <- fmt.Errorf("expected EHLO, got %q", string(buf[:n]))
				return
			}
			_, _ = conn.Write([]byte("250-localhost\r\n250 PIPELINING\r\n"))

			// 3. Read MAIL FROM
			n, err = conn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "MAIL FROM") {
				errChan <- fmt.Errorf("expected MAIL FROM, got %q", string(buf[:n]))
				return
			}
			_, _ = conn.Write([]byte("250 2.1.0 OK\r\n"))

			// 4. Read RCPT TO
			n, err = conn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "RCPT TO") {
				errChan <- fmt.Errorf("expected RCPT TO, got %q", string(buf[:n]))
				return
			}
			_, _ = conn.Write([]byte("250 2.1.5 OK\r\n"))

			// 5. Read DATA
			n, err = conn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "DATA") {
				errChan <- fmt.Errorf("expected DATA, got %q", string(buf[:n]))
				return
			}
			_, _ = conn.Write([]byte("354 Start mail input\r\n"))

			// 6. Read Mail Body
			_, err = conn.Read(buf)
			if err != nil {
				errChan <- fmt.Errorf("expected mail body read")
				return
			}
			_, _ = conn.Write([]byte("250 2.0.0 OK\r\n"))

			// 7. Read QUIT
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("221 2.0.0 Bye\r\n"))

			errChan <- nil
		}()

		err = sendMailWithTimeout(host, port, "", "", "from@example.com", []string{"to@example.com"}, []byte("Subject: Test\r\n\r\nBody"))
		if err != nil {
			t.Errorf("expected sendMailWithTimeout to succeed, got %v", err)
		}

		select {
		case err := <-errChan:
			if err != nil {
				t.Errorf("mock SMTP server error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("timeout waiting for mock SMTP server")
		}
	})

	t.Run("SendMailWithTimeout_TLSEncryptionRequiredError", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer lis.Close()

		host, port, _ := net.SplitHostPort(lis.Addr().String())

		errChan := make(chan error, 1)
		go func() {
			conn, err := lis.Accept()
			if err != nil {
				errChan <- err
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			// 1. Greeting
			_, _ = conn.Write([]byte("220 localhost ESMTP\r\n"))

			// 2. Read EHLO (Server advertises NO STARTTLS support)
			n, err := conn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "EHLO") {
				errChan <- fmt.Errorf("expected EHLO")
				return
			}
			_, _ = conn.Write([]byte("250-localhost\r\n250 PIPELINING\r\n"))

			// Client should stop here and return error because TLS is required for auth but not supported
			errChan <- nil
		}()

		err = sendMailWithTimeout(host, port, "user", "pass", "from@example.com", []string{"to@example.com"}, []byte("Subject: Test\r\n\r\nBody"))
		if err == nil {
			t.Error("expected error due to auth required but TLS unsupported")
		} else if !strings.Contains(err.Error(), "TLS is required for authentication") {
			t.Errorf("unexpected error: %v", err)
		}

		select {
		case err := <-errChan:
			if err != nil {
				t.Errorf("mock SMTP server error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("timeout waiting for mock SMTP server")
		}
	})

	t.Run("NewEmailSenderAndSendEmail", func(t *testing.T) {
		sender := NewEmailSender("localhost", "25", "", "", "from@example.com")
		if sender == nil {
			t.Fatal("expected NewEmailSender to return a sender")
		}

		// Missing configuration error paths
		sErr1 := NewEmailSender("", "25", "", "", "from@example.com")
		if err := sErr1.SendEmail("to@example.com", "Subj", "Body"); err == nil {
			t.Error("expected error for empty host")
		}

		sErr2 := NewEmailSender("localhost", "", "", "", "from@example.com")
		if err := sErr2.SendEmail("to@example.com", "Subj", "Body"); err == nil {
			t.Error("expected error for empty port")
		}

		sErr3 := NewEmailSender("localhost", "25", "", "", "")
		if err := sErr3.SendEmail("to@example.com", "Subj", "Body"); err == nil {
			t.Error("expected error for empty sender")
		}

		// Invalid recipient email error path
		if err := sender.SendEmail("bad-email", "Subj", "Body"); err == nil {
			t.Error("expected error for invalid recipient")
		}

		// Invalid sender email error path
		sErr4 := NewEmailSender("localhost", "25", "", "", "bad-email")
		if err := sErr4.SendEmail("to@example.com", "Subj", "Body"); err == nil {
			t.Error("expected error for invalid sender email")
		}
	})
}
