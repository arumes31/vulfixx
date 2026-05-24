package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// CSPReportPayload matches the standard browser CSP violation report JSON structure.
type CSPReportPayload struct {
	CSPReport struct {
		DocumentURI       string `json:"document-uri"`
		Referrer          string `json:"referrer"`
		BlockedURI        string `json:"blocked-uri"`
		ViolatedDirective string `json:"violated-directive"`
		OriginalPolicy    string `json:"original-policy"`
		Disposition       string `json:"disposition"`
		StatusCode        int    `json:"status-code"`
		SourceFile        string `json:"source-file"`
		LineNumber        int    `json:"line-number"`
		ColumnNumber      int    `json:"column-number"`
	} `json:"csp-report"`
}

// CSPReportHandler receives and logs browser Content Security Policy violation reports.
func (a *App) CSPReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 1MB to prevent excessive memory consumption
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

	var payload CSPReportPayload
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		log.Printf("CSP Report Error: Failed to decode CSP report body: %v", err)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	rep := payload.CSPReport
	log.Printf("CSP VIOLATION DETECTED: Document=%s, Blocked=%s, Directive=%s, Line=%d, Col=%d",
		sanitizeURI(rep.DocumentURI), sanitizeURI(rep.BlockedURI), sanitizeDirective(rep.ViolatedDirective), rep.LineNumber, rep.ColumnNumber)

	// Return a 204 No Content response
	w.WriteHeader(http.StatusNoContent)
}

func sanitizeURI(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid-uri]"
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

func sanitizeDirective(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
