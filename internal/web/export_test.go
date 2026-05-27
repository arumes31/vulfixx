package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestExportCVEsHandler(t *testing.T) {
	t.Run("Unauthorized", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		rr := httptest.NewRecorder()

		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/login" {
			t.Errorf("expected redirect to /login, got %s", loc)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		now := time.Now().Truncate(time.Second)
		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id,.*priority`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, now, "P0").
				AddRow("CVE-2023-0002", "Desc 2", 5.0, false, now, "P3"))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if rr.Header().Get("Content-Type") != "text/csv" {
			t.Errorf("expected text/csv, got %s", rr.Header().Get("Content-Type"))
		}

		body := rr.Body.String()
		header := "CVE ID,Description,CVSS Score,CISA KEV,Published Date,Priority"
		if !strings.Contains(body, header) {
			t.Errorf("expected body to contain header, got: %s", body)
		}
		if !strings.Contains(body, "CVE-2023-0001,Desc 1,9.8,true,"+now.Format("2006-01-02")+",P0") {
			t.Errorf("expected body to contain first row, got: %s", body)
		}
		if !strings.Contains(body, "CVE-2023-0002,Desc 2,5.0,false,"+now.Format("2006-01-02")+",P3") {
			t.Errorf("expected body to contain second row, got: %s", body)
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

		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id`).
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

		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
				AddRow("CVE-2023-0001", "Desc 1", "not-a-float", true, time.Now(), "P1"))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK (even with scan errors), got %d", rr.Code)
		}
		// The scan error should skip the row, so only header should be present
		if strings.Contains(rr.Body.String(), "CVE-2023-0001") {
			t.Errorf("did not expect body to contain CVE-2023-0001 due to scan error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("IterationError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		now := time.Now()
		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, now, "P0").
				RowError(1, fmt.Errorf("iteration error")))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

type failingResponseWriter struct {
	http.ResponseWriter
	failAt    int
	currWrite int
}

func (f *failingResponseWriter) Write(b []byte) (int, error) {
	if f.currWrite == f.failAt {
		return 0, fmt.Errorf("triggered write error")
	}
	f.currWrite++
	return f.ResponseWriter.Write(b)
}

func (f *failingResponseWriter) Header() http.Header {
	return f.ResponseWriter.Header()
}

func (f *failingResponseWriter) WriteHeader(statusCode int) {
	f.ResponseWriter.WriteHeader(statusCode)
}

func TestExportCVEsHandler_WriteErrors(t *testing.T) {
	t.Run("FailAtHeaderWrite", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, time.Now(), "P0"))

		rr := httptest.NewRecorder()
		fw := &failingResponseWriter{ResponseWriter: rr, failAt: 0}
		app.ExportCVEsHandler(fw, req)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FailAtRowWrite", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		largeDesc := strings.Repeat("A", 1000)
		rows := pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"})
		for i := 0; i < 10; i++ {
			rows.AddRow(fmt.Sprintf("CVE-2023-%04d", i), largeDesc, 7.5, false, time.Now(), "P2")
		}

		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(rows)

		rr := httptest.NewRecorder()
		fw := &failingResponseWriter{ResponseWriter: rr, failAt: 1}
		app.ExportCVEsHandler(fw, req)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FailAtFlush", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`(?is)SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date", "priority"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, time.Now(), "P0"))

		rr := httptest.NewRecorder()
		fw := &failingResponseWriter{ResponseWriter: rr, failAt: 1}
		app.ExportCVEsHandler(fw, req)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
