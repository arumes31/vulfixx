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

		// Expectations for PublicDashboardHandler
		// Metrics query should have no args if search, dates, and CVSS are empty/defaults
		mock.ExpectQuery("SELECT").WithArgs().WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit"}).AddRow(100, 10, 5))
		
		// Main query should have 2 args (pageSize, offset) if others are empty
		mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id, c.description, c.cvss_score, vector_string, c.cisa_kev, c.published_date, c.updated_date, 'active' as status, c.references, '' as notes FROM cves c")).
			WithArgs(20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes"}).
				AddRow(1, "CVE-2024-0001", "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, ""))
		
		mock.ExpectQuery("SELECT.*COUNT.*FILTER").WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low"}).AddRow(0, 1, 0, 0))

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

		mock.ExpectQuery("SELECT").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"total_cves", "kev_count", "critical_count", "in_progress_count"}).
				AddRow(100, 5, 10, 2))

		now := time.Now()
		mock.ExpectQuery("SELECT DISTINCT").WithArgs(1, 20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes"}).
				AddRow(1, "CVE-2024-0001", "Test CVE", 7.5, "CVSS:3.1/...", false, now, now, "active", []string{"http://example.com"}, "some notes"))

		mock.ExpectQuery("SELECT.*COUNT.*DISTINCT.*cvss_score").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low"}).AddRow(0, 1, 0, 0))

		mock.ExpectQuery("SELECT.*COUNT.*DISTINCT.*status").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"active", "prog", "res", "ign"}).AddRow(1, 0, 0, 0))

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
		mock.ExpectQuery(`SELECT id, cve_id, description, cvss_score, vector_string, cisa_kev, published_date, updated_date, 'active' as status, references, epss_score, cwe_id, cwe_name, github_poc_count FROM cves WHERE cve_id = \$1`).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count"}).
				AddRow(1, cveID, "Test description", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, time.Now(), time.Now(), "active", "[]", 0.5, "CWE-79", "XSS", 10))

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

		mock.ExpectQuery(`SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, time.Now()).
				AddRow("CVE-2023-0002", "Desc 2", 5.0, false, time.Now()))

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
