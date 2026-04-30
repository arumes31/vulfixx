package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestSitemapHandler_Caching(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// 1. First request: Should query DB and populate cache
	mock.ExpectQuery("SELECT cve_id, updated_at").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id", "updated_at"}).
			AddRow("CVE-2023-CACHE", time.Now()))

	req1 := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr1 := httptest.NewRecorder()
	app.SitemapHandler(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr1.Code)
	}
	if !strings.Contains(rr1.Body.String(), "CVE-2023-CACHE") {
		t.Errorf("Response body missing expected CVE ID: %s", rr1.Body.String())
	}

	// 2. Second request: Should serve from cache, NOT query DB
	// miniredis was started in setupTestApp, so a.Redis is not nil and functional.
	req2 := httptest.NewRequest("GET", "/sitemap.xml", nil)
	rr2 := httptest.NewRecorder()
	app.SitemapHandler(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("Expected status OK for second request, got %v", rr2.Code)
	}
	if rr2.Body.String() != rr1.Body.String() {
		t.Errorf("Expected cached response to match original response")
	}

	// Ensure all expectations were met (none for the second call)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
