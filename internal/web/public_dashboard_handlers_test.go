package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"cve-tracker/internal/db"
	"cve-tracker/internal/models"

	"github.com/pashagolub/pgxmock/v3"
)

func TestPublicDashboardHandler_DefaultView_CacheMiss(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Pre-seed global statsCache with ALL needed stats to avoid DB queries for metrics and stats
	statsCache.Lock()
	statsCache.total = 1
	statsCache.kevCount = 0
	statsCache.critCount = 0
	statsCache.severityCounts = SeverityCounts{Medium: 1}
	statsCache.topCWEs = []CWEStat{{ID: "CWE-1", Name: "A", Count: 1}}
	statsCache.epssDist = []int{1, 0, 0, 0}
	statsCache.Unlock()

	req, _ := http.NewRequest("GET", "/public", nil)

	// 1. Main CVE list
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(201, "CVE-2024-0001", "Desc", 5.0, "V", false,
			time.Now(), time.Now(), "active", []string{},
			0.1, "CWE-1", "A", 0, 0, "", []byte("{}"), "V", "P", []byte("[]"), "P3"))

	// 2. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs([]int{201}).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(201, false))

	// 3. Trending CVEs
	mock.ExpectQuery("SELECT c.id, c.cve_id.*FROM cves c").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products",
		}).AddRow(202, "CVE-2024-0002", "Trending", 9.6, "V", true,
			time.Now(), time.Now(), "active", []string{}, 0.1, "CWE-2", "B", 1, 0, "", []byte("{}"), "V", "P", []byte("[]")))

	rr := httptest.NewRecorder()
	app.PublicDashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestPublicDashboardHandler_CacheHit(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Pre-seed Redis
	cacheKey := "public_dashboard_default_v2"
	cachedData := PublicDashboardData{
		CVEs:      []models.CVE{{CVEID: "CVE-CACHED"}},
		Total:     1,
		MetaTitle: "Cached Title",
		Trending:  []models.CVE{},
	}
	jsonData, _ := json.Marshal(cachedData)
	app.Redis.Set(context.Background(), cacheKey, jsonData, 0)

	req, _ := http.NewRequest("GET", "/public", nil)
	rr := httptest.NewRecorder()
	app.PublicDashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	// Expectations: No DB queries should be made if cache is hit
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestPublicDashboardHandler_AJAX(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Pre-seed global statsCache
	statsCache.Lock()
	statsCache.total = 1
	statsCache.kevCount = 0
	statsCache.critCount = 0
	statsCache.severityCounts = SeverityCounts{Medium: 1}
	statsCache.topCWEs = []CWEStat{{ID: "CWE-1", Name: "A", Count: 1}}
	statsCache.epssDist = []int{1, 0, 0, 0}
	statsCache.Unlock()

	req, _ := http.NewRequest("GET", "/public?ajax=true", nil)

	// 1. Main CVE list
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(301, "CVE-2024-AJAX", "Desc", 5.0, "V", false,
			time.Now(), time.Now(), "active", []string{},
			0.1, "CWE-1", "A", 0, 0, "", []byte("{}"), "V", "P", []byte("[]"), "P3"))

	// 2. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs([]int{301}).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(301, false))

	// 3. Trending CVEs
	mock.ExpectQuery("SELECT c.id, c.cve_id.*FROM cves c").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products",
		}).AddRow(302, "CVE-2024-0002", "Trending", 9.6, "V", true,
			time.Now(), time.Now(), "active", []string{}, 0.1, "CWE-2", "B", 1, 0, "", []byte("{}"), "V", "P", []byte("[]")))

	rr := httptest.NewRecorder()
	app.PublicDashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Errorf("expected JSON content type, got %s", rr.Header().Get("Content-Type"))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestPublicDashboardHandler_QueryErrors(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// We need to trigger non-default whereClause to avoid statsCache
	req, _ := http.NewRequest("GET", "/public?q=error", nil)

	// 1. Metrics query error
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs("%error%").
		WillReturnError(fmt.Errorf("metrics error"))

	// 2. Main CVE list error
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs("%error%", 20, 0).
		WillReturnError(fmt.Errorf("query error"))

	// 3. Stats error
	mock.ExpectQuery("SELECT.*COUNT.*FILTER.*cvss_score").
		WithArgs("%error%").
		WillReturnError(fmt.Errorf("stats error"))

	// Trending CVEs error
	mock.ExpectQuery("SELECT c.id, c.cve_id.*FROM cves c").
		WillReturnError(fmt.Errorf("trending error"))

	rr := httptest.NewRecorder()
	app.PublicDashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
