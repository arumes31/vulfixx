package web

import (
	"bytes"
	"cve-tracker/internal/db"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateCVEStatusHandler_MissingSession(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	req := httptest.NewRequest("POST", "/api/status", bytes.NewReader([]byte(`{"cve_id": 1, "status": "resolved"}`)))
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
