package web

import (
	"context"
	"cve-tracker/internal/db"
	"fmt"
	"github.com/pashagolub/pgxmock/v3"
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDashboardHandler_Unauthenticated(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()

	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected status code %d, got %d", http.StatusFound, rr.Code)
	}
	if rr.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got %s", rr.Header().Get("Location"))
	}
}

func TestDashboardHandler_Authenticated_Default(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics (12 columns)
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	// 2. CVE List (22 columns)
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Test Description", 7.5, "CVSS:3.1/...", false,
			time.Now(), time.Now(), "active", []string{}, "Test Notes",
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "Vendor", "Product", []byte("[]"), "P2"))

	// 3. CISA Ransomware (1 column) - called inside the loop for each CVE
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. CWE Distribution (3 columns)
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-79", "Cross-site Scripting", 1))

	// 5. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_GlobalView(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard?all=true", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Test Description", 7.5, "CVSS:3.1/...", false,
			time.Now(), time.Now(), "active", []string{}, "Test Notes",
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "Vendor", "Product", []byte("[]"), "P2"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-79", "Cross-site Scripting", 1))

	// 5. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_Search(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard?q=testsearch", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID, "%testsearch%").
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, "%testsearch%", 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Test Description", 7.5, "CVSS:3.1/...", false,
			time.Now(), time.Now(), "active", []string{}, "Test Notes",
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "Vendor", "Product", []byte("[]"), "P2"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID, "%testsearch%").
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-79", "Cross-site Scripting", 1))

	// 5. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_TeamView(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1
	teamID := 10

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	// Mock team_id in session
	session, _ := app.SessionStore.Get(req, "vulfixx-session")
	session.Values["user_id"] = userID
	session.Values["team_id"] = teamID
	rr_session := httptest.NewRecorder()
	_ = session.Save(req, rr_session)
	for _, cookie := range rr_session.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID, teamID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, teamID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Test Description", 7.5, "CVSS:3.1/...", false,
			time.Now(), time.Now(), "active", []string{}, "Test Notes",
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "Vendor", "Product", []byte("[]"), "P2"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID, teamID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-79", "Cross-site Scripting", 1))

	// 5. RenderTemplate queries
				mock.ExpectQuery("(?is)SELECT.*u.onboarding_completed.*FROM users u").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed", "sub_count", "active_team_name"}).AddRow(true, 1, nil))



	mock.ExpectQuery("(?is)SELECT t.id, t.name FROM teams t").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(teamID, "Team10"))

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_Filters(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard?kev=true&status=in_progress&min_cvss=9.0&max_cvss=9.9&start_date=2023-01-01&end_date=2023-12-31", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID, 9.0, 9.9, "2023-01-01", "2023-12-31").
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0))

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 9.0, 9.9, "2023-01-01", "2023-12-31", 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-9999", "Critical KEV", 9.8, "CVSS:3.1/...", true,
			time.Now(), time.Now(), "in_progress", []string{}, "Notes",
			0.9, "CWE-78", "OS Injection", 5, 10, "exploit", []byte("{}"), "Vendor", "Product", []byte("[]"), "P1"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, true))

	// 4. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID, 9.0, 9.9, "2023-01-01", "2023-12-31").
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-78", "OS Command Injection", 1))

	// 5. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_DBError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics returns error
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnError(context.DeadlineExceeded)

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		})) // Empty rows

	// 3. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}))

	// 4. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestPublicDashboardHandler_WithFilters(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	// Use a query param to change whereClause from " WHERE (1=1) "
	req, _ := http.NewRequest("GET", "/public?q=test&vendor=oracle&product=java&cve=CVE-2023-1234&kev=true&min_cvss=5.0&max_cvss=9.0&start_date=2023-01-01&end_date=2023-12-31&cwe=CWE-79&has_poc=true&min_epss=0.1&max_epss=0.5", nil)

	// argIdx tracker:
	// q:
	// vendor:
	// product:
	// cve:
	// kev: true (no arg)
	// min_cvss:
	// max_cvss:
	// start_date:
	// end_date:
	// cwe:
	// has_poc: true (no arg)
	// min_epss: 0
	// max_epss: 1

	args := []interface{}{"%test%", "%oracle%", "%java%", "%CVE-2023-1234%", 5.0, 9.0, "2023-01-01", "2023-12-31", "%CWE-79%", 0.1, 0.5}

	// 1. Metrics query
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(args...).
		WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit"}).AddRow(1, 1, 0))

	// 2. Main CVE list
	// LIMIT: 2, OFFSET: 3
	listArgs := append(args, 20, 0)
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(listArgs...).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Desc", 7.5, "V", true,
			time.Now(), time.Now(), "active", []string{},
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "V", "P", []byte("[]"), "P2"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. Combined Stats Distribution
	mock.ExpectQuery("SELECT.*COUNT.*FILTER.*cvss_score.*COUNT.*FILTER.*epss_score").
		WithArgs(args...).
		WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low", "e1", "e2", "e3", "e4"}).AddRow(0, 1, 0, 0, 1, 0, 0, 0))

	// 5. CWE distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(args...).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 1))

	// 7. Trending CVEs
	mock.ExpectQuery("SELECT c.id, c.cve_id.*FROM cves c").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products",
		}).AddRow(102, "CVE-2023-5678", "Trending", 8.0, "V", false,
			time.Now(), time.Now(), "active", []string{}, 0.1, "CWE-1", "A", 1, 0, "", []byte("{}"), "V", "P", []byte("[]")))

	rr := httptest.NewRecorder()
	app.PublicDashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestRenderAJAX(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*App)
		renderData map[string]interface{}
		wantStatus int
		wantBody   string
	}{
		{
			name: "Success",
			setup: func(a *App) {
				// templates are loaded in setupTestApp
			},
			renderData: map[string]interface{}{"Key": "Value"},
			wantStatus: http.StatusOK,
			wantBody:   `{"html":"","meta":{"Key":"Value"}}`,
		},
		{
			name: "Template not found",
			setup: func(a *App) {
				a.TemplateMu.Lock()
				delete(a.TemplateMap, "public_dashboard.html")
				a.TemplateMu.Unlock()
			},
			renderData: map[string]interface{}{"Key": "Value"},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Template not found\n",
		},
		{
			name: "Template execution error",
			setup: func(a *App) {
				a.TemplateMu.Lock()
				// Load an invalid template mapping (no "cve_rows" defined in text/template)
				a.TemplateMap["public_dashboard.html"] = template.Must(template.New("empty").Parse(""))
				a.TemplateMu.Unlock()
			},
			renderData: map[string]interface{}{"Key": "Value"},
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Internal error\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
			}
			defer mock.Close()
			app := setupTestApp(t, mock)

			tt.setup(app)

			rr := httptest.NewRecorder()
			app.renderAJAX(rr, tt.renderData)

			if status := rr.Code; status != tt.wantStatus {
				t.Errorf("renderAJAX() status = %v, want %v", status, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				body := rr.Body.String()
				if !strings.Contains(body, `"html":`) || !strings.Contains(body, `"meta":{"Key":"Value"}`) {
					t.Errorf("renderAJAX() body = %v, want to contain %v", body, tt.wantBody)
				}
			} else {
				if rr.Body.String() != tt.wantBody {
					t.Errorf("renderAJAX() body = %v, want %v", rr.Body.String(), tt.wantBody)
				}
			}
		})
	}
}

func TestDashboardHandler_AllWithStatus(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard?all=true&status=in_progress", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID, "in_progress").
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0))

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, "in_progress", 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Test Description", 7.5, "V", false,
			time.Now(), time.Now(), "in_progress", []string{}, nil,
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "Vendor", "Product", []byte("[]"), "P2"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID, "in_progress").
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-79", "XSS", 1))

	// 5. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_RedisCacheHit(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, userID, false)

	// First run to seed cache
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(10, 2, 1, 3, 1, 4, 3, 2, 5, 3, 1, 1))

	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}))

	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}))

	expectBaseQueries(mock, userID)

	rr1 := httptest.NewRecorder()
	app.DashboardHandler(rr1, req)
	if rr1.Code != http.StatusOK {
		t.Errorf("first request failed: %d", rr1.Code)
	}

	// Second run should hit cache for metrics
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}))

	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}))

	expectBaseQueries(mock, userID)

	rr2 := httptest.NewRecorder()
	app.DashboardHandler(rr2, req)

	if rr2.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr2.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_ScanError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	// 2. CVE List - return a row that will fail Scan (e.g. wrong type for id)
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow("not-an-int", "CVE-2023-1234", "Desc", 7.5, "V", false,
			time.Now(), time.Now(), "active", []string{}, nil,
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "V", "P", []byte("[]"), "P2"))

	// 3. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}))

	// 4. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_CWEError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, userID, false)

	// 1. Consolidated Metrics
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	// 2. CVE List
	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}).AddRow(101, "CVE-2023-1234", "Desc", 7.5, "V", false,
			time.Now(), time.Now(), "active", []string{}, nil,
			0.1, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "V", "P", []byte("[]"), "P2"))

	// 3. CISA Ransomware
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(101, false))

	// 4. CWE Distribution returns error
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnError(fmt.Errorf("db error"))

	// 5. RenderTemplate queries
	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestDashboardHandler_InvalidStatus(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard?status=invalid", nil)
	setSessionUser(t, app, req, userID, false)

	// Status should be reset to empty, so query should look like default
	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev",
			"published_date", "updated_date", "status", "references", "notes",
			"epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits",
			"greynoise_classification", "osv_data", "vendor", "product",
			"affected_products", "priority",
		}))

	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}))

	expectBaseQueries(mock, userID)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestDashboardHandler_QueryError(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	userID := 1

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, userID, false)

	mock.ExpectQuery("SELECT.*COUNT.*total_cves").
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{
			"total_cves", "kev_count", "critical_count", "in_progress_count",
			"sev_crit", "sev_high", "sev_med", "sev_low",
			"stat_active", "stat_prog", "stat_res", "stat_ign",
		}).AddRow(1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0))

	mock.ExpectQuery("SELECT c.id, c.cve_id").
		WithArgs(userID, 20, 0).
		WillReturnError(fmt.Errorf("query error"))

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status code %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}
