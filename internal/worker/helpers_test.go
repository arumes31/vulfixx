package worker

import (
	"fmt"
	"net/http"
	"testing"
)

type EmailSenderMock struct {
	Count       int
	LastTo      string
	LastSubject string
}

func (m *EmailSenderMock) SendEmail(to, subject, body string) error {
	m.Count++
	m.LastTo = to
	m.LastSubject = subject
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

type EmailSenderMockV2 struct {
	Count int
	Err   error
}

func (m *EmailSenderMockV2) SendEmail(to, subject, body string) error {
	m.Count++
	return m.Err
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

	t.Run("RedactToken", func(t *testing.T) {
		if redactToken("1234567890") != "12345678..." {
			t.Errorf("redactToken failed: %s", redactToken("1234567890"))
		}
	})

	t.Run("RedactURL", func(t *testing.T) {
		url := "https://user:pass@example.com/path?query=1#frag"
		redacted := redactURL(url)
		if redacted != "https://example.com/" {
			t.Errorf("redactURL failed: %s", redacted)
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
	})
}
