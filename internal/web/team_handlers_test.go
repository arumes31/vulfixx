package web

import (
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v3"
)

func TestTeamsHandler(t *testing.T) {
	tests := []struct {
		name           string
		userID         int
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
	}{
		{
			name:   "Success",
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT t.id, t.name, t.invite_code, tm.role, t.created_at").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"id", "name", "invite_code", "role", "created_at"}).
						AddRow(1, "Team A", "ABC", "owner", time.Now()).
						AddRow(2, "Team B", "DEF", "member", time.Now()))
				// RenderTemplate expectations
				mock.ExpectQuery("SELECT onboarding_completed FROM users WHERE id = \\$1").WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed"}).AddRow(true))
				mock.ExpectQuery("SELECT t.id, t.name").WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Team A").AddRow(2, "Team B"))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "DB Error",
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT t.id, t.name, t.invite_code, tm.role").
					WithArgs(1).
					WillReturnError(fmt.Errorf("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
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

			req := httptest.NewRequest("GET", "/teams", nil)
			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["user_id"] = tt.userID
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest("GET", "/teams", nil)
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.TeamsHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func TestCreateTeamHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		form           url.Values
		userID         int
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "GET Redirect",
			method:         "GET",
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Missing Name",
			method:         "POST",
			form:           url.Values{"name": {""}},
			userID:         1,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Team name is required",
		},
		{
			name:   "Success",
			method: "POST",
			form:   url.Values{"name": {"New Team"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("INSERT INTO teams").
					WithArgs("New Team", pgxmock.AnyArg()).
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
				mock.ExpectExec("INSERT INTO team_members").
					WithArgs(1, 1).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Team created successfully",
		},
		{
			name:   "Duplicate Name",
			method: "POST",
			form:   url.Values{"name": {"Existing Team"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("INSERT INTO teams").
					WithArgs("Existing Team", pgxmock.AnyArg()).
					WillReturnError(&pgconn.PgError{Code: "23505"})
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Team name already exists",
		},
		{
			name:   "DB Begin Error",
			method: "POST",
			form:   url.Values{"name": {"New Team"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin().WillReturnError(fmt.Errorf("begin error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
		},
		{
			name:   "Insert Team Error",
			method: "POST",
			form:   url.Values{"name": {"New Team"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("INSERT INTO teams").
					WithArgs("New Team", pgxmock.AnyArg()).
					WillReturnError(fmt.Errorf("insert error"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
		},
		{
			name:   "Insert Member Error",
			method: "POST",
			form:   url.Values{"name": {"New Team"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("INSERT INTO teams").
					WithArgs("New Team", pgxmock.AnyArg()).
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
				mock.ExpectExec("INSERT INTO team_members").
					WithArgs(1, 1).
					WillReturnError(fmt.Errorf("insert member error"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
		},
		{
			name:   "Commit Error",
			method: "POST",
			form:   url.Values{"name": {"New Team"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("INSERT INTO teams").
					WithArgs("New Team", pgxmock.AnyArg()).
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
				mock.ExpectExec("INSERT INTO team_members").
					WithArgs(1, 1).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectCommit().WillReturnError(fmt.Errorf("commit error"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
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

			req := httptest.NewRequest(tt.method, "/teams/create", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["user_id"] = tt.userID
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest(tt.method, "/teams/create", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.CreateTeamHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if tt.expectedBody != "" && !strings.Contains(rr2.Body.String(), tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rr2.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func TestJoinTeamHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		form           url.Values
		userID         int
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "GET Redirect",
			method:         "GET",
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Missing Invite Code",
			method:         "POST",
			form:           url.Values{"invite_code": {""}},
			userID:         1,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invite code is required",
		},
		{
			name:   "Invalid Invite Code",
			method: "POST",
			form:   url.Values{"invite_code": {"wrong"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id FROM teams WHERE invite_code =").
					WithArgs("wrong").
					WillReturnError(fmt.Errorf("not found"))
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid invite code",
		},
		{
			name:   "Success",
			method: "POST",
			form:   url.Values{"invite_code": {"abc"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id FROM teams WHERE invite_code =").
					WithArgs("abc").
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(10))
				mock.ExpectExec("INSERT INTO team_members").
					WithArgs(10, 1).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, "team_joined", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Joined workspace successfully",
		},
		{
			name:   "DB Error on Insert",
			method: "POST",
			form:   url.Values{"invite_code": {"abc"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT id FROM teams WHERE invite_code =").
					WithArgs("abc").
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(10))
				mock.ExpectExec("INSERT INTO team_members").
					WithArgs(10, 1).
					WillReturnError(fmt.Errorf("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
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

			req := httptest.NewRequest(tt.method, "/teams/join", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["user_id"] = tt.userID
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest(tt.method, "/teams/join", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.JoinTeamHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if tt.expectedBody != "" && !strings.Contains(rr2.Body.String(), tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rr2.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func TestLeaveTeamHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		form           url.Values
		userID         int
		activeTeamID   int
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Invalid Method",
			method:         "GET",
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "Invalid Team ID",
			method:         "POST",
			form:           url.Values{"team_id": {"abc"}},
			userID:         1,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid team ID",
		},
		{
			name:   "Not a Member",
			method: "POST",
			form:   url.Values{"team_id": {"10"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT role FROM team_members .* FOR UPDATE").
					WithArgs(10, 1).
					WillReturnError(fmt.Errorf("not member"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "You are not a member of this team",
		},
		{
			name:   "Last Owner Prevention",
			method: "POST",
			form:   url.Values{"team_id": {"10"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT role FROM team_members .* FOR UPDATE").
					WithArgs(10, 1).
					WillReturnRows(pgxmock.NewRows([]string{"role"}).AddRow("owner"))
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM team_members WHERE team_id = \\$1 AND role = 'owner'").
					WithArgs(10).
					WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "You are the last owner",
		},
		{
			name:         "Success Leave (Not Active)",
			method:       "POST",
			form:         url.Values{"team_id": {"10"}},
			userID:       1,
			activeTeamID: 20,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT role FROM team_members .* FOR UPDATE").
					WithArgs(10, 1).
					WillReturnRows(pgxmock.NewRows([]string{"role"}).AddRow("member"))
				mock.ExpectExec("DELETE FROM team_members").
					WithArgs(10, 1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, "team_left", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Left workspace",
		},
		{
			name:         "Success Leave (Active)",
			method:       "POST",
			form:         url.Values{"team_id": {"10"}},
			userID:       1,
			activeTeamID: 10,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT role FROM team_members .* FOR UPDATE").
					WithArgs(10, 1).
					WillReturnRows(pgxmock.NewRows([]string{"role"}).AddRow("member"))
				mock.ExpectExec("DELETE FROM team_members").
					WithArgs(10, 1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, "team_left", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Left workspace",
		},
		{
			name:   "DB Error on Delete",
			method: "POST",
			form:   url.Values{"team_id": {"10"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT role FROM team_members .* FOR UPDATE").
					WithArgs(10, 1).
					WillReturnRows(pgxmock.NewRows([]string{"role"}).AddRow("member"))
				mock.ExpectExec("DELETE FROM team_members").
					WithArgs(10, 1).
					WillReturnError(fmt.Errorf("db error"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
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

			req := httptest.NewRequest(tt.method, "/teams/leave", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["user_id"] = tt.userID
			session.Values["team_id"] = tt.activeTeamID
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest(tt.method, "/teams/leave", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.LeaveTeamHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if tt.expectedBody != "" && !strings.Contains(rr2.Body.String(), tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rr2.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

func TestSwitchTeamHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		form           url.Values
		userID         int
		referer        string
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
	}{
		{
			name:           "Invalid Method",
			method:         "GET",
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "Forbidden",
			method: "POST",
			form:   url.Values{"team_id": {"10"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(10, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:    "Success Switch to Team",
			method:  "POST",
			form:    url.Values{"team_id": {"10"}},
			userID:  1,
			referer: "/some-page",
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(10, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
			},
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Success Switch to Private",
			method:         "POST",
			form:           url.Values{"team_id": {"0"}},
			userID:         1,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusFound,
		},
		{
			name:   "DB Error",
			method: "POST",
			form:   url.Values{"team_id": {"10"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(10, 1).
					WillReturnError(fmt.Errorf("db error"))
			},
			expectedStatus: http.StatusForbidden,
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

			req := httptest.NewRequest(tt.method, "/teams/switch", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["user_id"] = tt.userID
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest(tt.method, "/teams/switch", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.SwitchTeamHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr2.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}
