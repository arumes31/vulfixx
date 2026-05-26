<<<<<<< HEAD
﻿package web

import (
        "bytes"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "testing"

        "cve-tracker/internal/db"
        "github.com/pashagolub/pgxmock/v3"
)

func TestUpdateCVEStatusHandler_MissingSession(t *testing.T) {
        mock, err := db.SetupTestDB()
        if err != nil {
                t.Fatalf("failed to setup mock db: %v", err)
        }
        defer mock.Close()
        app := setupTestApp(t, mock)

        req := httptest.NewRequest("POST", "/api/status", bytes.NewReader([]byte(` + "`" + `{"cve_id": 1, "status": "resolved"}` + "`" + `)))
        req.Header.Set("Accept", "application/json")
        rr := httptest.NewRecorder()
        app.UpdateCVEStatusHandler(rr, req)

        if rr.Code != http.StatusUnauthorized {
                t.Errorf("expected status 401 Unauthorized, got %d", rr.Code)
        }

        var resp map[string]interface{}
        if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                t.Fatalf("failed to decode response: %v", err)
        }
        if msg, _ := resp["error"].(string); msg != "Unauthorized" {
                t.Errorf("expected error 'Unauthorized', got '%v'", msg)
        }
}

func TestBulkUpdateCVEStatusHandler_New(t *testing.T) {
        mock, err := db.SetupTestDB()
        if err != nil {
                t.Fatalf("failed to setup mock db: %v", err)
        }
        defer mock.Close()
        app := setupTestApp(t, mock)

        t.Run("Method Not Allowed", func(t *testing.T) {
                req := httptest.NewRequest("GET", "/api/status/bulk", nil)
                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusMethodNotAllowed {
                        t.Errorf("expected 405, got %d", rr.Code)
                }
        })

        t.Run("Unauthorized", func(t *testing.T) {
                req := httptest.NewRequest("POST", "/api/status/bulk", nil)
                req.Header.Set("Accept", "application/json")
                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusUnauthorized {
                        t.Errorf("expected 401, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Error   string ` + "`" + `json:"error"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if resp.Success || resp.Error != "Unauthorized" {
                        t.Errorf("expected success=false, error=Unauthorized, got %+v", resp)
                }
        })

        t.Run("Bad Request - Invalid JSON", func(t *testing.T) {
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBufferString("invalid"))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)
                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusBadRequest {
                        t.Errorf("expected 400, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Error   string ` + "`" + `json:"error"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if resp.Success || resp.Error != "Bad request" {
                        t.Errorf("expected success=false, error=Bad request, got %+v", resp)
                }
        })

        t.Run("Invalid Status", func(t *testing.T) {
                body, _ := json.Marshal(map[string]interface{}{
                        "cve_ids": []int{1, 2},
                        "status":  "invalid",
                })
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBuffer(body))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)
                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusBadRequest {
                        t.Errorf("expected 400, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Error   string ` + "`" + `json:"error"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if resp.Success || resp.Error != "Invalid status" {
                        t.Errorf("expected success=false, error=Invalid status, got %+v", resp)
                }
        })

        t.Run("Empty CVE IDs", func(t *testing.T) {
                body, _ := json.Marshal(map[string]interface{}{
                        "cve_ids": []int{},
                        "status":  "resolved",
                })
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBuffer(body))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)
                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusOK {
                        t.Errorf("expected 200, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Message string ` + "`" + `json:"message"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if !resp.Success || resp.Message != "No CVEs selected" {
                        t.Errorf("expected success=true, message=No CVEs selected, got %+v", resp)
                }
        })

        t.Run("Too many CVE IDs", func(t *testing.T) {
                ids := make([]int, 1001)
                body, _ := json.Marshal(map[string]interface{}{
                        "cve_ids": ids,
                        "status":  "resolved",
                })
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBuffer(body))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)
                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusBadRequest {
                        t.Errorf("expected 400, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Error   string ` + "`" + `json:"error"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if resp.Success || resp.Error != "Too many CVE IDs (max 1000)" {
                        t.Errorf("expected success=false, error=Too many CVE IDs (max 1000), got %+v", resp)
                }
        })

        t.Run("Forbidden - Not Team Member", func(t *testing.T) {
                body, _ := json.Marshal(map[string]interface{}{
                        "cve_ids": []int{1, 2},
                        "status":  "resolved",
                })
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBuffer(body))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)

                // Set team ID in session
                session, _ := app.SessionStore.Get(req, "vulfixx-session")
                session.Values["team_id"] = 10
                _ = session.Save(req, httptest.NewRecorder())

                mock.ExpectQuery("SELECT EXISTS").WithArgs(10, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusForbidden {
                        t.Errorf("expected 403, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Error   string ` + "`" + `json:"error"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if resp.Success || resp.Error != "Forbidden: You are not a member of this team" {
                        t.Errorf("expected success=false, error=Forbidden..., got %+v", resp)
                }
        })

        t.Run("Success - Personal Active (Delete)", func(t *testing.T) {
                body, _ := json.Marshal(map[string]interface{}{
                        "cve_ids": []int{1, 2},
                        "status":  "active",
                })
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBuffer(body))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)

                mock.ExpectBegin()
                mock.ExpectExec("DELETE FROM user_cve_status").WithArgs([]int{1, 2}, 1).WillReturnResult(pgxmock.NewResult("DELETE", 2))
                mock.ExpectCommit()
                mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "cve_status_bulk_updated", "Bulk updated 2 CVEs to active", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusOK {
                        t.Errorf("expected 200, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Message string ` + "`" + `json:"message"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if !resp.Success || resp.Message != "Updated 2 CVEs" {
                        t.Errorf("expected success=true, message=Updated 2 CVEs, got %+v", resp)
                }
        })

        t.Run("Success - Team Resolved (Insert/Update)", func(t *testing.T) {
                body, _ := json.Marshal(map[string]interface{}{
                        "cve_ids": []int{1, 2},
                        "status":  "resolved",
                })
                req := httptest.NewRequest("POST", "/api/status/bulk", bytes.NewBuffer(body))
                req.Header.Set("Accept", "application/json")
                setSessionUser(t, app, req, 1, false)

                // Set team ID in session
                session, _ := app.SessionStore.Get(req, "vulfixx-session")
                session.Values["team_id"] = 10
                _ = session.Save(req, httptest.NewRecorder())

                mock.ExpectQuery("SELECT EXISTS").WithArgs(10, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
                mock.ExpectBegin()
                mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(1, pgxmock.AnyArg(), "resolved", []int{1, 2}).WillReturnResult(pgxmock.NewResult("INSERT", 2))
                mock.ExpectCommit()
                mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "cve_status_bulk_updated", "Bulk updated 2 CVEs to resolved", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

                rr := httptest.NewRecorder()
                app.BulkUpdateCVEStatusHandler(rr, req)
                if rr.Code != http.StatusOK {
                        t.Errorf("expected 200, got %d", rr.Code)
                }
                var resp struct {
                        Success bool   ` + "`" + `json:"success"` + "`" + `
                        Message string ` + "`" + `json:"message"` + "`" + `
                }
                if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
                        t.Fatalf("failed to decode response: %v", err)
                }
                if !resp.Success || resp.Message != "Updated 2 CVEs" {
                        t.Errorf("expected success=true, message=Updated 2 CVEs, got %+v", resp)
                }
        })
}

=======
package web

import (
	"context"
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = ")).
		WithArgs(101).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = ")).
		WithArgs(101).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = ")).
		WithArgs(101).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = ")).
		WithArgs(101).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

	// 4. CWE Distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(userID, teamID).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).
			AddRow("CWE-79", "Cross-site Scripting", 1))

	// 5. RenderTemplate queries
	mock.ExpectQuery(regexp.QuoteMeta("SELECT onboarding_completed FROM users WHERE id = ")).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed"}).AddRow(true))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM user_subscriptions WHERE user_id = ")).
		WithArgs(userID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = ")).
		WithArgs(101).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(true))

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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cisa_ransomware FROM cves WHERE id = ")).
		WithArgs(101).
		WillReturnRows(pgxmock.NewRows([]string{"cisa_ransomware"}).AddRow(false))

	// 4. Severity Distribution
	mock.ExpectQuery("SELECT.*COUNT.*FILTER.*cvss_score").
		WithArgs(args...).
		WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low"}).AddRow(0, 1, 0, 0))

	// 5. CWE distribution
	mock.ExpectQuery("SELECT cwe_id, COALESCE.*MAX.*cwe_name.*COUNT").
		WithArgs(args...).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "max_cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 1))

	// 6. EPSS distribution
	mock.ExpectQuery("SELECT.*COUNT.*FILTER.*epss_score").
		WithArgs(args...).
		WillReturnRows(pgxmock.NewRows([]string{"e1", "e2", "e3", "e4"}).AddRow(1, 0, 0, 0))

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
}
>>>>>>> pr210
