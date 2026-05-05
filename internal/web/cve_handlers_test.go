package web

import (
	"bytes"
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestIndexHandler(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		// Populate cache to avoid DB hits for metrics
		statsCache.Lock()
		statsCache.total = 100
		statsCache.kevCount = 10
		statsCache.critCount = 5
		statsCache.severityCounts = SeverityCounts{High: 1}
		statsCache.topCWEs = []CWEStat{{ID: "CWE-79", Name: "XSS", Count: 1}}
		statsCache.epssDist = []int{1, 0, 0, 0}
		statsCache.Unlock()

		// Main query should have 2 args (pageSize, offset) if others are empty
		mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, c.published_date, c.updated_date, 'active' as status, COALESCE(c.\"references\", '{}'), COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0), COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'), COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority FROM cves c WHERE (1=1) ORDER BY c.published_date DESC NULLS LAST, c.id DESC LIMIT $1 OFFSET $2")).
			WithArgs(20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
				AddRow(1, "CVE-2024-0001", "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, 0.123, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "", "", []byte("[]"), "P2"))

		// Trending CVEs
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
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

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

func TestDashboardHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/dashboard", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/dashboard", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT.*COUNT.*total_cves.*kev_count.*critical_count.*in_progress_count.*sev_crit.*sev_high.*sev_med.*sev_low.*stat_active.*stat_prog.*stat_res.*stat_ign").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit", "prog", "sev_crit", "sev_high", "sev_med", "sev_low", "stat_active", "stat_prog", "stat_res", "stat_ign"}).
				AddRow(100, 10, 5, 2, 5, 1, 0, 0, 1, 0, 0, 0))

		mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, c.published_date, c.updated_date, COALESCE(ucs.status, 'active') as status, COALESCE(c.\"references\", '{}'), ucn.notes, COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0), COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'), COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority")).
			WithArgs(1, 20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
				AddRow(1, "CVE-2024-0001", "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, "", 0.123, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "", "", []byte("[]"), "P1"))

		mock.ExpectQuery("SELECT cwe_id.*COUNT.*cnt.*FROM cves").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "name", "cnt"}).AddRow("CWE-79", "XSS", 1))

		expectBaseQueries(mock, 1)
		rr2 := httptest.NewRecorder()
		app.DashboardHandler(rr2, req)

		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestBulkUpdateCVEStatusHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 2))
		mock.ExpectCommit()
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req := httptest.NewRequest("POST", "/api/status/bulk", strings.NewReader(`{"cve_ids": [101, 102], "status": "resolved"}`))
		req.Header.Set("Accept", "application/json")
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/status/bulk", strings.NewReader(`{"cve_ids": [101, 102], "status": "resolved"}`))
		req.Header.Set("Accept", "application/json")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		app.BulkUpdateCVEStatusHandler(rr2, req)

		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestCVEDetailHandler_Extra(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-2023-1234"
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cve_id, description, COALESCE(cvss_score, 0), vector_string, cisa_kev, published_date, updated_date, 'active' as status, \"references\", COALESCE(epss_score, 0), COALESCE(cwe_id, ''), COALESCE(cwe_name, ''), COALESCE(github_poc_count, 0), COALESCE(greynoise_hits, 0), COALESCE(greynoise_classification, ''), osv_data, configurations, COALESCE(vendor, ''), COALESCE(product, ''), COALESCE(affected_products, '[]'), COALESCE(darknet_mentions, 0), darknet_last_seen, COALESCE(priority, 'P3') as priority")).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "configurations", "vendor", "product", "affected_products", "darknet_mentions", "darknet_last_seen", "priority"}).
				AddRow(1, cveID, "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, 0.123, "CWE-79", "XSS", 1, 0, "", []byte("{}"), []byte("[]"), "", "", []byte("[]"), 0, nil, "P0"))

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": cveID})
		rr := httptest.NewRecorder()

		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-NOT-FOUND"
		mock.ExpectQuery(`SELECT .* FROM cves WHERE cve_id = \$1`).
			WithArgs(cveID).
			WillReturnError(pgx.ErrNoRows)

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": cveID})
		rr := httptest.NewRecorder()

		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-ERROR"
		mock.ExpectQuery(`SELECT .* FROM cves WHERE cve_id = \$1`).
			WithArgs(cveID).
			WillReturnError(fmt.Errorf("db error"))

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": cveID})
		rr := httptest.NewRecorder()

		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestExportCVEsHandler_Extra(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id,.*priority`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, time.Now(), "P0").
				AddRow("CVE-2023-0002", "Desc 2", 5.0, false, time.Now(), "P3"))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if rr.Header().Get("Content-Type") != "text/csv" {
			t.Errorf("expected text/csv, got %s", rr.Header().Get("Content-Type"))
		}
		if !strings.Contains(rr.Body.String(), "CVE-2023-0001") {
			t.Errorf("expected body to contain CVE-2023-0001")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("ScanError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date"}).
				AddRow("CVE-2023-0001", "Desc 1", "not-a-float", true, time.Now()))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK (even with scan errors), got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestUpdateCVENoteHandler(t *testing.T) {
	t.Run("Success_Private", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "test notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "test notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cve_notes")).WithArgs(1, pgxmock.AnyArg(), 1, "test notes").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).WithArgs(1, "cve_note_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr2 := httptest.NewRecorder()
		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Success_Team", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "team notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		session.Values["team_id"] = 10
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "team notes"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery(regexp.QuoteMeta("SELECT EXISTS")).WithArgs(10, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cve_notes")).WithArgs(1, pgxmock.AnyArg(), 1, "team notes").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_activity_logs")).WithArgs(1, "cve_note_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr2 := httptest.NewRecorder()
		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
