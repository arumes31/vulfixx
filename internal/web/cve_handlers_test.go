package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"cve-tracker/internal/db"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

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
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cve_id, description, COALESCE(cvss_score, 0), vector_string, cisa_kev, published_date, updated_date, 'active' as status, \"references\", COALESCE(epss_score, 0), COALESCE(epss_percentile, 0), COALESCE(cwe_id, ''), COALESCE(cwe_name, ''), COALESCE(github_poc_count, 0), COALESCE(greynoise_hits, 0), COALESCE(greynoise_classification, ''), osv_data, vendor_advisories, configurations, COALESCE(vendor, ''), COALESCE(product, ''), COALESCE(affected_products, '[]'), COALESCE(priority, 'P3') as priority, COALESCE(exploit_available, false), COALESCE(osint_data, '{}'), COALESCE(inthewild_data, '{}'), greynoise_last_updated, osv_last_updated, inthewild_last_updated, COALESCE(cisa_kev_data, '{}'), COALESCE(reference_tags, '{}'), COALESCE(github_poc_repos, '[]')")).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "epss_percentile", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor_advisories", "configurations", "vendor", "product", "affected_products", "priority", "exploit_available", "osint_data", "inthewild_data", "greynoise_last_updated", "osv_last_updated", "inthewild_last_updated", "cisa_kev_data", "reference_tags", "github_poc_repos"}).
				AddRow(1, cveID, "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, 0.123, 0.0, "CWE-79", "XSS", 1, 0, "", []byte("{}"), []byte("{}"), []byte("[]"), "", "", []byte("[]"), "P0", false, []byte("{}"), []byte("{}"), nil, nil, nil, []byte("{}"), []string{}, []byte("[]")))

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
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", cveID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
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
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", cveID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
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

	t.Run("OptimisticLock_Conflict", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "stale notes", "version": 5}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/notes", bytes.NewReader([]byte(`{"cve_id": 1, "notes": "stale notes", "version": 5}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET version = version + 1 WHERE id = $1 AND version = $2")).
			WithArgs(1, 5).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		rr2 := httptest.NewRecorder()
		app.UpdateCVENoteHandler(rr2, req)
		if rr2.Code != http.StatusConflict {
			t.Errorf("expected 409 Conflict, got %d", rr2.Code)
		}
		if !strings.Contains(rr2.Body.String(), "Conflict") {
			t.Errorf("expected conflict message in body, got: %s", rr2.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestAPICVEsHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("SuccessWithoutCursor", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, c.published_date, c.updated_date, 'active' as status, COALESCE(c.\"references\", '{}'), COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0), COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'), COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority FROM cves c WHERE (1=1) ORDER BY c.published_date DESC NULLS LAST, c.id DESC LIMIT $1")).
			WithArgs(20).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
				AddRow(1, "CVE-2024-0001", "Desc", 8.0, "", false, time.Now(), time.Now(), "active", []string{}, 0.1, "CWE-89", "SQLi", 0, 0, "", []byte("{}"), "V", "P", []byte("[]"), "P1"))

		req := httptest.NewRequest("GET", "/api/cves", nil)
		rr := httptest.NewRecorder()
		app.APICVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "CVE-2024-0001") {
			t.Errorf("expected CVE-2024-0001 in body, got %s", rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestCVEDetailHandler_LoggedIn(t *testing.T) {
	t.Run("SuccessWithUserAndPagination", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-2023-9999"
		userID := 123
		publishedDate := time.Now().Add(-24 * time.Hour).Truncate(time.Second)

		// Primary CVE Query
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT
		id, cve_id, description, COALESCE(cvss_score, 0), vector_string, cisa_kev,
		published_date, updated_date, 'active' as status, "references",
		COALESCE(epss_score, 0), COALESCE(epss_percentile, 0), COALESCE(cwe_id, ''), COALESCE(cwe_name, ''), COALESCE(github_poc_count, 0),
		COALESCE(greynoise_hits, 0), COALESCE(greynoise_classification, ''), osv_data,
		vendor_advisories, configurations, COALESCE(vendor, ''), COALESCE(product, ''), COALESCE(affected_products, '[]'),
		COALESCE(priority, 'P3') as priority,
		COALESCE(exploit_available, false), COALESCE(osint_data, '{}'), COALESCE(inthewild_data, '{}'),
		greynoise_last_updated, osv_last_updated, inthewild_last_updated,
		COALESCE(cisa_kev_data, '{}'), COALESCE(reference_tags, '{}'), COALESCE(github_poc_repos, '[]')
		FROM cves
		WHERE cve_id = $1`)).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "epss_percentile", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor_advisories", "configurations", "vendor", "product", "affected_products", "priority", "exploit_available", "osint_data", "inthewild_data", "greynoise_last_updated", "osv_last_updated", "inthewild_last_updated", "cisa_kev_data", "reference_tags", "github_poc_repos"}).
				AddRow(1, cveID, "Detailed Test", 9.9, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, publishedDate, time.Now(), "active", []string{"http://ref.com"}, 0.99, 0.0, "CWE-89", "SQLi", 10, 5, "High", []byte("{}"), []byte("{}"), []byte("[]"), "VendorX", "ProductY", []byte("[]"), "P0", true, []byte("{}"), []byte("{}"), nil, nil, nil, []byte("{}"), []string{}, []byte("[]")))

		// CISA Ransomware Query
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE cve_id = $1")).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(true))

		// Threat Associations Query
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, cve_id, entity_name, entity_type, source, created_at
		FROM cve_threat_associations
		WHERE cve_id = $1
		ORDER BY entity_name ASC`)).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "entity_name", "entity_type", "source", "created_at"}).
				AddRow(1, cveID, "Actor1", "Threat Actor", "CISA", time.Now()))

		// Next ID Query
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT cve_id FROM cves
			WHERE published_date < $1 OR (published_date = $1 AND id < $2)
			ORDER BY published_date DESC, id DESC LIMIT 1`)).
			WithArgs(publishedDate, 1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-OLDER"))

		// Prev ID Query
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT cve_id FROM cves
			WHERE published_date > $1 OR (published_date = $1 AND id > $2)
			ORDER BY published_date ASC, id ASC LIMIT 1`)).
			WithArgs(publishedDate, 1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-NEWER"))

		// User Assets Query
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT a.name, COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}')
			FROM assets a
			LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
			WHERE a.user_id = $1 OR a.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1)
			GROUP BY a.id, a.name`)).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"name", "keywords"}).
				AddRow("Asset1", []string{"key1", "key2"}))

		// Base Queries in RenderTemplate
		expectBaseQueries(mock, userID)

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		setSessionUser(t, app, req, userID, false)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", cveID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
