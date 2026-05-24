package web

import (
	"context"
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func BenchmarkDashboardHandler(b *testing.B) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	// Locate the templates/ directory
	_ = findTemplatesDir()

	app := setupTestApp(&testing.T{}, mock)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Mock metrics query
		mock.ExpectQuery("(?is)SELECT.*total_cves.*kev_count.*critical_count.*in_progress_count.*sev_crit.*sev_high.*sev_med.*sev_low.*stat_active.*stat_prog.*stat_res.*stat_ign").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit", "prog", "sev_crit", "sev_high", "sev_med", "sev_low", "stat_active", "stat_prog", "stat_res", "stat_ign"}).
				AddRow(1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0))

		// Mock main CVEs query
		mock.ExpectQuery("(?is)SELECT.*c.id, c.cve_id").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
				AddRow(1, "CVE-2023-1234", "Test", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, time.Now(), time.Now(), "in_progress", []string{}, "note", 0.5, "CWE-79", "XSS", 2, 0, "", []byte(`{}`), "V", "P", []byte(`[]`), "P0"))

		// Mock inner cisa_ransomware query
		mock.ExpectQuery("(?is)SELECT cisa_ransomware FROM cves").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

		// Mock CWE distribution query
		mock.ExpectQuery("(?is)SELECT cwe_id.*FROM cves").
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 1))

		expectBaseQueries(mock, 1)

		req := httptest.NewRequest("GET", "/dashboard", nil)
		setSessionUser(&testing.T{}, app, req, 1, false)

		rr := httptest.NewRecorder()
		app.DashboardHandler(rr, req)

		if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
			b.Fatalf("handler returned wrong status code: got %v want %v or %v", rr.Code, http.StatusOK, http.StatusFound)
		}

		app.Redis.FlushAll(context.Background())
	}
}
