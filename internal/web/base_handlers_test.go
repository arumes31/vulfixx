package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestIndexHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("NotFound", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/non-existent-path-123", nil)
		rr := httptest.NewRecorder()
		app.IndexHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found, got %d", rr.Code)
		}
	})

	t.Run("Unauthenticated", func(t *testing.T) {
		// Populate cache to avoid DB hits for metrics
		statsCache.Lock()
		statsCache.total = 100
		statsCache.kevCount = 10
		statsCache.critCount = 5
		statsCache.severityCounts = SeverityCounts{High: 1}
		statsCache.topCWEs = []CWEStat{{ID: "CWE-79", Name: "XSS", Count: 1}}
		statsCache.epssDist = []int{1, 0, 0, 0}
		statsCache.Unlock()

		// 1. Main query
		// Columns (21): id, cve_id, description, cvss_score, vector_string, cisa_kev, published_date, updated_date, status, references, epss_score, cwe_id, cwe_name, github_poc_count, greynoise_hits, greynoise_classification, osv_data, vendor, product, affected_products, priority
		mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, c.published_date, c.updated_date, 'active' as status, COALESCE(c.\"references\", '{}'), COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0), COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'), COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority FROM cves c WHERE (1=1) ORDER BY c.published_date DESC NULLS LAST, c.id DESC LIMIT $1 OFFSET $2")).
			WithArgs(20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
				AddRow(1, "CVE-2024-0001", "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, 0.123, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "", "", []byte("[]"), "P2"))

		// 2. Ransomware check for scanning results
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = $1")).WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

		// 3. Trending CVEs query
		// Columns (20): id, cve_id, description, cvss_score, vector_string, cisa_kev, published_date, updated_date, status, references, epss_score, cwe_id, cwe_name, github_poc_count, greynoise_hits, greynoise_classification, osv_data, vendor, product, affected_products
		mock.ExpectQuery("SELECT.*c.id, c.cve_id.*FROM cves c.*ORDER BY c.github_poc_count DESC").WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products"}).
			AddRow(2, "CVE-2024-9999", "Trending", 9.8, "", true, time.Now(), time.Now(), "active", []string{}, 0.9, "CWE-89", "SQLi", 5, 0, "", []byte("{}"), "", "", []byte("[]")))

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		app.IndexHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		app.IndexHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
