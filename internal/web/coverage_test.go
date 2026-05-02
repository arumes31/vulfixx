package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/pashagolub/pgxmock/v3"
)

func TestCoverage_CVEDetailHandler(t *testing.T) {
	StopStatsTicker()
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	// Mock CVE query
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cve_id")).
		WithArgs("CVE-2024-TEST").
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss", "vector", "kev", "pub", "upd", "status", "refs", "epss", "cwe_id", "cwe_name", "poc", "gn_hits", "gn_class", "osv", "conf", "vendor", "product", "affected"}).
			AddRow(1, "CVE-2024-TEST", "Desc", 8.0, "V", false, time.Now(), time.Now(), "active", []string{}, 0.5, "CWE-1", "Name", 0, 0, "", []byte(`{}`), []byte(`[]`), "V", "P", []byte(`[]`)))

	// Mock Next/Prev queries
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE published_date < $1")).WillReturnRows(pgxmock.NewRows([]string{"cve_id"}))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE published_date > $1")).WillReturnRows(pgxmock.NewRows([]string{"cve_id"}))

	r := mux.NewRouter()
	r.HandleFunc("/cve/{id}", app.CVEDetailHandler)
	
	req, _ := http.NewRequest("GET", "/cve/CVE-2024-TEST", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_LogoutHandler(t *testing.T) {
	StopStatsTicker()
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	req, _ := http.NewRequest("POST", "/logout", nil)
	setSessionUser(t, app, req, 1, false)
	
	rr := httptest.NewRecorder()
	app.LogoutHandler(rr, req)
	
	if rr.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", rr.Code)
	}
}

func TestCoverage_VerifyEmailHandler(t *testing.T) {
	StopStatsTicker()
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	// auth.VerifyEmail uses db.Pool
	db.Pool = mock
	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET is_email_verified = TRUE, email_verify_token = NULL WHERE email_verify_token = $1")).
		WithArgs("valid-token").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	
	req, _ := http.NewRequest("GET", "/verify-email?token=valid-token", nil)
	rr := httptest.NewRecorder()
	app.VerifyEmailHandler(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_AdminUserManagementHandler(t *testing.T) {
	StopStatsTicker()
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	req, _ := http.NewRequest("GET", "/admin/users", nil)
	setSessionUser(t, app, req, 1, true) // Admin
	
	// AdminMiddleware query
	mock.ExpectQuery(regexp.QuoteMeta("SELECT is_admin FROM users WHERE id = $1")).
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(true))
	
	// Handler query
	mock.ExpectQuery("SELECT id, email, is_email_verified, is_admin, created_at FROM users").
		WillReturnRows(pgxmock.NewRows([]string{"id", "email", "is_email_verified", "is_admin", "created_at"}).
			AddRow(1, "admin@example.com", true, true, time.Now()))

	// RenderTemplate queries
	expectBaseQueries(mock, 1)
	
	rr := httptest.NewRecorder()
	app.AdminMiddleware(http.HandlerFunc(app.AdminUserManagementHandler)).ServeHTTP(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_BulkUpdateCVEStatusHandler(t *testing.T) {
	StopStatsTicker()
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	req, _ := http.NewRequest("POST", "/dashboard/bulk-update", strings.NewReader("cve_ids=CVE-1,CVE-2&status=resolved"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest") // For JSON response
	setSessionUser(t, app, req, 1, false)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified FROM users WHERE id = $1")).WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"is_verified"}).AddRow(true))

	// Mock resolving IDs
	mock.ExpectQuery("SELECT id FROM cves WHERE cve_id = ANY").WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(101).AddRow(102))

	mock.ExpectExec("INSERT INTO user_cve_status").WillReturnResult(pgxmock.NewResult("INSERT", 2))

	rr := httptest.NewRecorder()
	app.AuthMiddleware(http.HandlerFunc(app.BulkUpdateCVEStatusHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_RSSFeedHandler(t *testing.T) {
	StopStatsTicker()
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	mock.ExpectQuery("SELECT id FROM users WHERE rss_feed_token = $1").
		WithArgs("token123").
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	
	mock.ExpectQuery("SELECT DISTINCT c.cve_id").
		WithArgs(1, 0.0, "").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "published_date"}).
			AddRow("CVE-RSS-1", "Desc", 7.0, time.Now()))
	
	req, _ := http.NewRequest("GET", "/feed?token=token123", nil)
	rr := httptest.NewRecorder()
	app.RSSFeedHandler(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/rss+xml" {
		t.Errorf("wrong content type")
	}
}

func TestCoverage_RobotsHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	req, _ := http.NewRequest("GET", "/robots.txt", nil)
	rr := httptest.NewRecorder()
	app.RobotsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_SitemapHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id, updated_at FROM cves")).
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow("CVE-SITEMAP-1", time.Now()))

	req, _ := http.NewRequest("GET", "/sitemap.xml", nil)
	rr := httptest.NewRecorder()
	app.SitemapHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_ExportCVEsHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	req, _ := http.NewRequest("GET", "/export", nil)
	setSessionUser(t, app, req, 1, false)

	mock.ExpectQuery("SELECT DISTINCT c.cve_id").
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date"}).
			AddRow("CVE-EXPORT-1", "Desc", 9.0, true, time.Now()))

	rr := httptest.NewRecorder()
	app.ExportCVEsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_HealthzHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	req, _ := http.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	app.HealthzHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestCoverage_ReadyzHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	mock.ExpectPing()
	
	req, _ := http.NewRequest("GET", "/readyz", nil)
	rr := httptest.NewRecorder()
	app.ReadyzHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}
