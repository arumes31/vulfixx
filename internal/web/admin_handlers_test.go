package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestAdminUserManagementHandler(t *testing.T) {
	tests := []struct {
		name           string
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
	}{
		{
			name: "Success",
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id, email, is_email_verified, is_admin, created_at").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "is_email_verified", "is_admin", "created_at"}).
						AddRow(1, "admin@test.com", true, true, time.Now()).
						AddRow(2, "user@test.com", true, false, time.Now()))

				// RenderTemplate expectations
				mock.ExpectQuery("SELECT t.id, t.name").WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Team A"))
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("failed to setup mock db: %v", err)
			}
			defer mock.Close()
			app := setupTestApp(t, mock)
			tt.mockExpect(mock)

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

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func TestAdminDeleteUserHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		form           url.Values
		userID         int
		csrfInSession  string
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
	}{
		{
			name:          "Success",
			method:        "POST",
			form:          url.Values{"id": {"2"}, "csrf_token": {"correct"}},
			userID:        1,
			csrfInSession: "correct",
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("DELETE FROM users WHERE id =").
					WithArgs(2).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, "user_delete", "Deleted user ID 2", pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("failed to setup mock db: %v", err)
			}
			defer mock.Close()
			app := setupTestApp(t, mock)
			tt.mockExpect(mock)

			req := httptest.NewRequest(tt.method, "/admin/users/delete", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			if tt.userID != 0 {
				session.Values["user_id"] = tt.userID
				session.Values["is_admin"] = true
			}
			if tt.csrfInSession != "" {
				session.Values["admin_csrf_token"] = tt.csrfInSession
			}
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest(tt.method, "/admin/users/delete", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.AdminDeleteUserHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

