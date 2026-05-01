package web

import (
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
		mock.ExpectQuery(`SELECT\s+COUNT\(DISTINCT c.id\) as total_cves`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"total_cves", "kev_count", "critical_count", "in_progress_count"}).
				AddRow(1, 1, 1, 1))

		// Mock main CVEs query
		mock.ExpectQuery(`SELECT DISTINCT c.id, c.cve_id, c.description`).
			WithArgs(1, 20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes", "epss_score", "cwe_id", "cwe_name", "github_poc_count"}).
				AddRow(1, "CVE-2023-1234", "Test", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, time.Now(), time.Now(), "in_progress", []string{}, "note", 0.5, "CWE-79", "XSS", 2))

		expectBaseQueries(mock, 1)

		req := httptest.NewRequest("GET", "/dashboard", nil)
		setSessionUser(&testing.T{}, app, req, 1, false)

		rr := httptest.NewRecorder()
		app.DashboardHandler(rr, req)

		if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
			b.Fatalf("handler returned wrong status code: got %v want %v or %v", rr.Code, http.StatusOK, http.StatusFound)
		}
	}
}
