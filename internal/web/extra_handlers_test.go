package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestRobotsHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("SetupTestDB failed: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	rr := httptest.NewRecorder()

	app.RobotsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
	if rr.Body.String() == "" {
		t.Errorf("expected robots.txt content, got empty")
	}
}

func TestAlertHistoryHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("SetupTestDB failed: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	app := setupTestApp(t, mock)
	req := httptest.NewRequest("GET", "/alerts", nil)
	setSessionUser(t, app, req, 1, false)

	// Main alert history query
	mock.ExpectQuery("(?i)SELECT ah\\.sent_at, c\\.cve_id, c\\.description, c\\.cvss_score FROM alert_history ah JOIN cves c ON ah\\.cve_id = c\\.id WHERE ah\\.user_id = \\$1 ORDER BY ah\\.sent_at DESC LIMIT 100").
		WithArgs(1).
		WillReturnRows(mock.NewRows([]string{"sent_at", "cve_id", "description", "cvss_score"}))

	expectBaseQueries(mock, 1)

	rr := httptest.NewRecorder()
	app.AlertHistoryHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}

func TestCompleteOnboardingHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("SetupTestDB failed: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	app := setupTestApp(t, mock)
	req := httptest.NewRequest("POST", "/complete-onboarding", nil)
	setSessionUser(t, app, req, 1, false)

	mock.ExpectExec("(?i)UPDATE users SET onboarding_completed = TRUE WHERE id = \\$1").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	rr := httptest.NewRecorder()
	app.CompleteOnboardingHandler(rr, req)

	// SendResponse with redirect sends 302
	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 Found, got %d", rr.Code)
	}
}
