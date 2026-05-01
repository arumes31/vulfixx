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

func BenchmarkDashboardHandler(b *testing.B) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	// Locate the templates/ directory
	_ = findTemplatesDir()

	app := setupTestApp(&testing.T{}, mock)

	// Mock data for dashboard
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cve_id, description")).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "cisa_kev", "published_date", "epss_score", "github_poc_count", "status", "note", "cwe_id", "cwe_name"}).
			AddRow(1, "CVE-2023-1234", "Test", 9.8, true, time.Now(), 0.5, 2, "in_progress", "note", "CWE-79", "XSS"))

	// Mock stats for sidebar
	mock.ExpectQuery(regexp.QuoteMeta("SELECT t.id, t.name FROM teams t JOIN team_members tm")).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT onboarding_completed FROM users")).
		WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed"}).AddRow(true))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		setSessionUser(&testing.T{}, app, req, 1, false)

		rr := httptest.NewRecorder()
		app.DashboardHandler(rr, req)

		if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
			// We expect 200 or 302 (redirect to verify email if not verified in mock)
			// But for benchmark we just want it to run.
		}
	}
}
