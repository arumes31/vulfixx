package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSPReportHandler(t *testing.T) {
	app := &App{}

	t.Run("InvalidMethod", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/csp-report", nil)
		rr := httptest.NewRecorder()
		app.CSPReportHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/csp-report", strings.NewReader("bad-json"))
		rr := httptest.NewRecorder()
		app.CSPReportHandler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", rr.Code)
		}
	})

	t.Run("ValidReport", func(t *testing.T) {
		jsonReport := `{
			"csp-report": {
				"document-uri": "http://localhost:8080/dashboard",
				"referrer": "",
				"blocked-uri": "http://evil.com/malicious.js",
				"violated-directive": "script-src",
				"original-policy": "default-src 'self'",
				"disposition": "enforce",
				"status-code": 200,
				"source-file": "http://localhost:8080/dashboard",
				"line-number": 42,
				"column-number": 10
			}
		}`

		req := httptest.NewRequest("POST", "/api/csp-report", bytes.NewBufferString(jsonReport))
		rr := httptest.NewRecorder()
		app.CSPReportHandler(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("expected 204 No Content, got %d", rr.Code)
		}
	})
}
