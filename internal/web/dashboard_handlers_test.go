package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cve-tracker/internal/db"
	"github.com/pashagolub/pgxmock/v3"
)

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
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Message string `json:"message"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Message string `json:"message"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
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
			Success bool   `json:"success"`
			Message string `json:"message"`
		}
		json.NewDecoder(rr.Body).Decode(&resp)
		if !resp.Success || resp.Message != "Updated 2 CVEs" {
			t.Errorf("expected success=true, message=Updated 2 CVEs, got %+v", resp)
		}
	})
}
