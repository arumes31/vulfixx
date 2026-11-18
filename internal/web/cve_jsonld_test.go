package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pashagolub/pgxmock/v5"
)

// ldJSONBlock extracts the contents of the <script type="application/ld+json">
// element rendered on the CVE detail page.
var ldJSONBlock = regexp.MustCompile(`(?s)<script type="application/ld\+json"[^>]*>(.*?)</script>`)

// TestCVEDetailHandler_JSONLDEscaped verifies that the JSON-LD block emitted by
// CVEDetailHandler is a valid, context-escaped JSON object. A hostile CVE
// description must not be able to break out of the <script> element, and the
// block must parse as a JSON object (not a double-encoded JSON string, which is
// what manual json.Marshal + string replacement produced before this fix).
func TestCVEDetailHandler_JSONLDEscaped(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	cveID := "CVE-2023-9999"
	// A description crafted to break out of the <script> block and to exercise
	// characters that must be escaped in a JSON/HTML script context.
	payload := `</script><script>alert('xss')</script><!-- & "quotes" ` + " end"

	mock.ExpectQuery(`SELECT .* FROM cves WHERE cve_id = \$1`).
		WithArgs(cveID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "epss_percentile", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor_advisories", "configurations", "vendor", "product", "affected_products", "priority", "exploit_available", "osint_data", "inthewild_data", "greynoise_last_updated", "osv_last_updated", "inthewild_last_updated", "cisa_kev_data", "reference_tags", "github_poc_repos"}).
			AddRow(1, cveID, payload, 7.5, "", false, time.Now(), time.Now(), "active", []string{}, 0.123, 0.0, "CWE-79", "XSS", 1, 0, "", []byte("{}"), []byte("{}"), []byte("[]"), "", "", []byte("[]"), "P0", false, []byte("{}"), []byte("{}"), nil, nil, nil, []byte("{}"), []string{}, []byte("[]")))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE cve_id = $1")).
		WithArgs(cveID).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cve_id, entity_name, entity_type, source, created_at FROM cve_threat_associations WHERE cve_id = $1 ORDER BY entity_name ASC")).
		WithArgs(cveID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "entity_name", "entity_type", "source", "created_at"}))

	req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", cveID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	app.CVEDetailHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	m := ldJSONBlock.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatal("no application/ld+json script block found in rendered page")
	}
	block := strings.TrimSpace(m[1])

	// The description must not be able to close the <script> element: no raw
	// '<' may survive into the JSON-LD block.
	if strings.Contains(block, "<") {
		t.Errorf("JSON-LD block contains an unescaped '<':\n%s", block)
	}

	// The block must be a JSON object. Manual marshal+replace emitted a quoted
	// JSON string literal instead, which fails to decode into a map.
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(block), &obj); err != nil {
		t.Fatalf("JSON-LD block is not a valid JSON object (likely double-encoded): %v\nblock: %s", err, block)
	}

	// The hostile payload must round-trip exactly through the escaping.
	if got, _ := obj["description"].(string); got != payload {
		t.Errorf("description did not round-trip.\n got: %q\nwant: %q", got, payload)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
