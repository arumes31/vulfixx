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

// The delete-operator form is guarded twice: the global gorilla/csrf middleware checks
// gorilla.csrf.Token, and AdminDeleteUserHandler separately calls App.ValidateCSRF,
// which reads csrf_token. Rendering only one of the two silently breaks deletion, so
// assert both are emitted.
func TestAdminUserManagementRendersBothCSRFTokens(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	mock.ExpectQuery("SELECT id, email, is_email_verified, is_admin, created_at").
		WillReturnRows(pgxmock.NewRows([]string{"id", "email", "is_email_verified", "is_admin", "created_at"}).
			AddRow(1, "admin@test.com", true, true, time.Now()).
			AddRow(2, "user@test.com", true, false, time.Now()))
	mock.ExpectQuery("SELECT onboarding_completed FROM users WHERE id = \\$1").WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed"}).AddRow(true))
	mock.ExpectQuery("SELECT t.id, t.name").WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Team A"))

	req := httptest.NewRequest("GET", "/admin/users", nil)
	session, _ := app.SessionStore.Get(req, "vulfixx-session")
	session.Values["user_id"] = 1
	session.Values["is_admin"] = true
	rr := httptest.NewRecorder()
	_ = session.Save(req, rr)

	req = httptest.NewRequest("GET", "/admin/users", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	rr2 := httptest.NewRecorder()
	app.AdminUserManagementHandler(rr2, req)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr2.Code)
	}
	body := rr2.Body.String()

	// user@test.com is not an admin, so its row renders the delete form.
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error(`missing csrf_token input; App.ValidateCSRF would reject every delete`)
	}
	if !strings.Contains(body, "gorilla.csrf.Token") {
		t.Error("missing gorilla.csrf.Token field; the csrf middleware would reject every delete")
	}
	if strings.Contains(body, `name="csrf_token" value=""`) {
		t.Error("csrf_token rendered empty; CSRFToken was not supplied to the template")
	}
}
