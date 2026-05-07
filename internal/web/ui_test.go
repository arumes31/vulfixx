package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gorilla/mux"
	"github.com/pashagolub/pgxmock/v3"
)

func TestUI_DashboardStructure(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(true)
	app := setupTestApp(t, mock)

	// Mock data for dashboard
	// Use (?is) for case-insensitive and dot-matches-newline matching
	mock.ExpectQuery("(?is)SELECT.*total_cves.*kev_count.*critical_count.*in_progress_count.*sev_crit.*sev_high.*sev_med.*sev_low.*stat_active.*stat_prog.*stat_res.*stat_ign").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit", "prog", "sev_crit", "sev_high", "sev_med", "sev_low", "stat_active", "stat_prog", "stat_res", "stat_ign"}).
			AddRow(10, 2, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0))
	mock.ExpectQuery("(?is)SELECT.*c.id, c.cve_id").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
		AddRow(1, "CVE-2024-UI", "UI Test", 9.0, "", true, time.Now(), time.Now(), "active", []string{}, "", 0.5, "CWE-1", "XSS", 0, 0, "", []byte(`{}`), "V", "P", []byte(`[]`), "P0"))
	mock.ExpectQuery("(?is)SELECT cwe_id.*FROM cves").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 1))

	expectBaseQueries(mock, 1)

	req, _ := http.NewRequest("GET", "/dashboard", nil)
	setSessionUser(t, app, req, 1, false)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	t.Run("CheckCriticalElements", func(t *testing.T) {
		if doc.Find("nav").Length() == 0 {
			t.Errorf("sidebar navigation not found")
		}
		if !strings.Contains(rr.Body.String(), "Threat Intelligence") {
			t.Errorf("Dashboard header not found")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestUI_RegisterPageStructure(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)
	app := setupTestApp(t, mock)
	expectBaseQueries(mock, 0)

	req, _ := http.NewRequest("GET", "/register", nil)
	rr := httptest.NewRecorder()
	app.RegisterHandler(rr, req)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	t.Run("CheckRegisterForm", func(t *testing.T) {
		if doc.Find("input[name='email']").Length() == 0 {
			t.Errorf("email input missing")
		}
		if doc.Find("input[name='password']").Length() == 0 {
			t.Errorf("password input missing")
		}
		if doc.Find("input[name='password_confirm']").Length() == 0 {
			t.Errorf("password_confirm input missing")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestUI_CVEDetailStructure(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)
	app := setupTestApp(t, mock)

	cveID := "CVE-2024-1234"
	mock.ExpectQuery("(?is)SELECT.*FROM cves WHERE cve_id =").
		WithArgs(cveID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "configurations", "vendor", "product", "affected_products", "darknet_mentions", "darknet_last_seen", "priority"}).
			AddRow(1, cveID, "Detailed description", 8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", false, time.Now(), time.Now(), "active", []string{"http://ref.com"}, 0.5, "CWE-79", "XSS", 1, 0, "", []byte(`{}`), []byte(`[]`), "V", "P", []byte(`[]`), 0, nil, "P2"))

	mock.ExpectQuery("(?is)SELECT cve_id FROM cves.*WHERE published_date <").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2024-1233"))
	mock.ExpectQuery("(?is)SELECT cve_id FROM cves.*WHERE published_date >").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2024-1235"))
	mock.ExpectQuery("(?is)SELECT a.name.*FROM assets").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"name", "keywords"}).AddRow("Server1", []string{"linux"}))

	expectBaseQueries(mock, 1)

	req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
	req = mux.SetURLVars(req, map[string]string{"id": cveID})
	setSessionUser(t, app, req, 1, false)

	rr := httptest.NewRecorder()
	app.CVEDetailHandler(rr, req)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	t.Run("CheckCVEDetails", func(t *testing.T) {
		if !strings.Contains(doc.Text(), cveID) {
			t.Errorf("CVE ID not found in page. Body: %s", rr.Body.String())
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestUI_SettingsPageStructure(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)
	app := setupTestApp(t, mock)

	mock.ExpectQuery("(?is)SELECT email, is_totp_enabled FROM users WHERE id =").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).AddRow("test@example.com", false))

	expectBaseQueries(mock, 1)

	req, _ := http.NewRequest("GET", "/settings", nil)
	setSessionUser(t, app, req, 1, false)

	rr := httptest.NewRecorder()
	app.SettingsHandler(rr, req)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	t.Run("CheckSettingsSections", func(t *testing.T) {
		body := rr.Body.String()
		if !strings.Contains(body, "System Preferences") || !strings.Contains(body, "Credentials") {
			t.Errorf("Settings sections (System Preferences or Credentials) not found")
		}
		if doc.Find("form").Length() == 0 {
			t.Errorf("settings form not found")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestUI_TeamPageStructure(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)
	app := setupTestApp(t, mock)

	// Mock for team list
	mock.ExpectQuery("(?is)SELECT t.id, t.name, t.invite_code, tm.role, t.created_at").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name", "invite_code", "role", "created_at"}).
			AddRow(1, "Team1", "INVITE123", "owner", time.Now()))

	expectBaseQueries(mock, 1)

	req, _ := http.NewRequest("GET", "/teams", nil)
	setSessionUser(t, app, req, 1, false)

	rr := httptest.NewRecorder()
	app.TeamsHandler(rr, req)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	t.Run("CheckTeamList", func(t *testing.T) {
		if !strings.Contains(doc.Text(), "Team1") {
			t.Errorf("Team name not found")
		}
		if !strings.Contains(rr.Body.String(), "INVITE123") {
			t.Errorf("Invite code not found")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
