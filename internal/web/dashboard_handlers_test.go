package web

import (
	"bytes"
	"cve-tracker/internal/db"
	"net/http/httptest"
	"strings"
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
	rr := httptest.NewRecorder()
	app.UpdateCVEStatusHandler(rr, req)

	if !strings.Contains(rr.Body.String(), "Unauthorized") {
		t.Errorf("expected unauthorized error in body, got: %s", rr.Body.String())
	}
}
