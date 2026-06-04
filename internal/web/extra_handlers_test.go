package web

import (
	"cve-tracker/internal/db"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

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

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestUpdateCVEStatusHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		userID         int
		activeTeamID   int
		body           string
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		expectedJSON   string
	}{
		{
			name:           "InvalidJSON",
			method:         "POST",
			userID:         1,
			body:           `{bad json`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Bad request",
		},
		{
			name:           "InvalidStatus",
			method:         "POST",
			userID:         1,
			body:           `{"cve_id": 10, "status": "invalid_status"}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Invalid status",
		},
		{
			name:         "ForbiddenTeamMember",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_id": 10, "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
			},
			expectedStatus: http.StatusForbidden,
			expectedJSON:   "Forbidden",
		},
		{
			name:   "OptimisticLockConflict",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "status": "resolved", "version": 2}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("UPDATE cves SET version").
					WithArgs(10, 2).
					WillReturnResult(pgxmock.NewResult("UPDATE", 0))
			},
			expectedStatus: http.StatusConflict,
			expectedJSON:   "Conflict",
		},
		{
			name:   "OptimisticLockDBError",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "status": "resolved", "version": 2}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("UPDATE cves SET version").
					WithArgs(10, 2).
					WillReturnError(errors.New("lock db fail"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   "Internal server error",
		},
		{
			name:   "Success_Active_NoTeam",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "status": "active"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("DELETE FROM user_cve_status WHERE cve_id").
					WithArgs(10, 1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Remediation status updated",
		},
		{
			name:         "Success_Resolved_WithTeam",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_id": 10, "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectExec("INSERT INTO user_cve_status").
					WithArgs(1, pgxmock.AnyArg(), 10, "resolved").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Remediation status updated",
		},
		{
			name:         "Success_Active_WithTeam",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_id": 10, "status": "active"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectExec("DELETE FROM user_cve_status WHERE cve_id").
					WithArgs(10, 5).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Remediation status updated",
		},
		{
			name:   "Success_Resolved_NoTeam",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("INSERT INTO user_cve_status").
					WithArgs(1, pgxmock.AnyArg(), 10, "resolved").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Remediation status updated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("setup mock db: %v", err)
			}
			defer mock.Close()
			mock.MatchExpectationsInOrder(false)

			app := setupTestApp(t, mock)
			tt.mockExpect(mock)

			req := httptest.NewRequest(tt.method, "/api/status", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")

			session, _ := app.SessionStore.Get(req, "vulfixx-session")
			session.Values["user_id"] = tt.userID
			if tt.activeTeamID > 0 {
				session.Values["team_id"] = tt.activeTeamID
			}
			rr := httptest.NewRecorder()
			_ = session.Save(req, rr)

			req = httptest.NewRequest(tt.method, "/api/status", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			for _, c := range rr.Result().Cookies() {
				req.AddCookie(c)
			}

			rr2 := httptest.NewRecorder()
			app.UpdateCVEStatusHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.expectedStatus, rr2.Code)
			}

			bodyStr := rr2.Body.String()
			if !strings.Contains(bodyStr, tt.expectedJSON) {
				t.Errorf("%s: expected JSON body to contain %q, got %q", tt.name, tt.expectedJSON, bodyStr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: unmet expectations: %v", tt.name, err)
			}
		})
	}
}

func TestUpdateCVENoteHandler_Detailed(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		userID         int
		activeTeamID   int
		body           string
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		expectedJSON   string
	}{
		{
			name:           "MethodNotAllowed",
			method:         "GET",
			userID:         1,
			body:           `{}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedJSON:   "Method not allowed",
		},
		{
			name:           "Unauthorized",
			method:         "POST",
			userID:         0, // no user
			body:           `{}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusUnauthorized,
			expectedJSON:   "Unauthorized",
		},
		{
			name:           "InvalidJSON",
			method:         "POST",
			userID:         1,
			body:           `{invalid json`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Bad request",
		},
		{
			name:           "NotesTooLong",
			method:         "POST",
			userID:         1,
			body:           `{"cve_id": 1, "notes": "` + strings.Repeat("a", 10001) + `"}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Notes too long",
		},
		{
			name:         "ForbiddenTeamMember",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_id": 10, "notes": "test note"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
			},
			expectedStatus: http.StatusForbidden,
			expectedJSON:   "Forbidden",
		},
		{
			name:   "OptimisticLockConflict",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "notes": "test note", "version": 2}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("UPDATE cves SET version").
					WithArgs(10, 2).
					WillReturnResult(pgxmock.NewResult("UPDATE", 0))
			},
			expectedStatus: http.StatusConflict,
			expectedJSON:   "Conflict",
		},
		{
			name:   "OptimisticLockDBError",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "notes": "test note", "version": 2}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("UPDATE cves SET version").
					WithArgs(10, 2).
					WillReturnError(errors.New("lock fail"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   "Internal server error",
		},
		{
			name:   "SuccessNoTeam",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "notes": "test note"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("INSERT INTO cve_notes").
					WithArgs(1, pgxmock.AnyArg(), 10, "test note").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Notes saved successfully",
		},
		{
			name:         "SuccessWithTeam",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_id": 10, "notes": "test note"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectExec("INSERT INTO cve_notes").
					WithArgs(1, pgxmock.AnyArg(), 10, "test note").
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Notes saved successfully",
		},
		{
			name:   "DBInsertError",
			method: "POST",
			userID: 1,
			body:   `{"cve_id": 10, "notes": "test note"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("INSERT INTO cve_notes").
					WithArgs(1, pgxmock.AnyArg(), 10, "test note").
					WillReturnError(errors.New("db error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("setup mock db: %v", err)
			}
			defer mock.Close()
			mock.MatchExpectationsInOrder(false)

			app := setupTestApp(t, mock)
			tt.mockExpect(mock)

			req := httptest.NewRequest(tt.method, "/api/notes", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")

			if tt.userID > 0 {
				session, _ := app.SessionStore.Get(req, "vulfixx-session")
				session.Values["user_id"] = tt.userID
				if tt.activeTeamID > 0 {
					session.Values["team_id"] = tt.activeTeamID
				}
				rr := httptest.NewRecorder()
				_ = session.Save(req, rr)

				req = httptest.NewRequest(tt.method, "/api/notes", strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
				for _, c := range rr.Result().Cookies() {
					req.AddCookie(c)
				}
			}

			rr2 := httptest.NewRecorder()
			app.UpdateCVENoteHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.expectedStatus, rr2.Code)
			}

			bodyStr := rr2.Body.String()
			if !strings.Contains(bodyStr, tt.expectedJSON) {
				t.Errorf("%s: expected JSON body to contain %q, got %q", tt.name, tt.expectedJSON, bodyStr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: unmet expectations: %v", tt.name, err)
			}
		})
	}
}

func TestBulkUpdateCVEStatusHandler_Detailed(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		userID         int
		activeTeamID   int
		body           string
		mockExpect     func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		expectedJSON   string
	}{
		{
			name:           "MethodNotAllowed",
			method:         "GET",
			userID:         1,
			body:           `{}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedJSON:   "Method not allowed",
		},
		{
			name:           "Unauthorized",
			method:         "POST",
			userID:         0,
			body:           `{}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusUnauthorized,
			expectedJSON:   "Unauthorized",
		},
		{
			name:           "InvalidJSON",
			method:         "POST",
			userID:         1,
			body:           `{invalid json`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Bad request",
		},
		{
			name:           "InvalidStatus",
			method:         "POST",
			userID:         1,
			body:           `{"cve_ids": [1], "status": "invalid"}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Invalid status",
		},
		{
			name:           "NoCVEsSelected",
			method:         "POST",
			userID:         1,
			body:           `{"cve_ids": [], "status": "resolved"}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusOK,
			expectedJSON:   "No CVEs selected",
		},
		{
			name:           "TooManyCVEs",
			method:         "POST",
			userID:         1,
			body:           `{"cve_ids": ` + strings.ReplaceAll(fmt.Sprintf("%v", make([]int, 1001)), " ", ",") + `, "status": "resolved"}`,
			mockExpect:     func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			expectedJSON:   "Too many CVE IDs",
		},
		{
			name:         "ForbiddenTeamMember",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_ids": [1], "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
			},
			expectedStatus: http.StatusForbidden,
			expectedJSON:   "Forbidden",
		},
		{
			name:   "BeginTransactionError",
			method: "POST",
			userID: 1,
			body:   `{"cve_ids": [1, 2], "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin().WillReturnError(errors.New("begin error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   "Internal server error",
		},
		{
			name:   "SuccessActiveNoTeam",
			method: "POST",
			userID: 1,
			body:   `{"cve_ids": [1, 2], "status": "active"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectExec("DELETE FROM user_cve_status").
					WithArgs(pgxmock.AnyArg(), 1).
					WillReturnResult(pgxmock.NewResult("DELETE", 2))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Updated 2 CVEs",
		},
		{
			name:         "SuccessActiveWithTeam",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_ids": [1, 2], "status": "active"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectBegin()
				mock.ExpectExec("DELETE FROM user_cve_status").
					WithArgs(pgxmock.AnyArg(), 5).
					WillReturnResult(pgxmock.NewResult("DELETE", 2))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Updated 2 CVEs",
		},
		{
			name:   "SuccessResolvedNoTeam",
			method: "POST",
			userID: 1,
			body:   `{"cve_ids": [1, 2], "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO user_cve_status").
					WithArgs(1, pgxmock.AnyArg(), "resolved", pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 2))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Updated 2 CVEs",
		},
		{
			name:         "SuccessResolvedWithTeam",
			method:       "POST",
			userID:       1,
			activeTeamID: 5,
			body:         `{"cve_ids": [1, 2], "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT EXISTS").
					WithArgs(5, 1).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO user_cve_status").
					WithArgs(1, pgxmock.AnyArg(), "resolved", pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 2))
				mock.ExpectCommit()
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedJSON:   "Updated 2 CVEs",
		},
		{
			name:   "ExecQueryError",
			method: "POST",
			userID: 1,
			body:   `{"cve_ids": [1, 2], "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO user_cve_status").
					WithArgs(1, pgxmock.AnyArg(), "resolved", pgxmock.AnyArg()).
					WillReturnError(errors.New("exec fail"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   "Internal server error",
		},
		{
			name:   "CommitTransactionError",
			method: "POST",
			userID: 1,
			body:   `{"cve_ids": [1, 2], "status": "resolved"}`,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO user_cve_status").
					WithArgs(1, pgxmock.AnyArg(), "resolved", pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 2))
				mock.ExpectCommit().WillReturnError(errors.New("commit fail"))
				mock.ExpectRollback()
			},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := db.SetupTestDB()
			if err != nil {
				t.Fatalf("setup mock db: %v", err)
			}
			defer mock.Close()
			mock.MatchExpectationsInOrder(false)

			app := setupTestApp(t, mock)
			tt.mockExpect(mock)

			req := httptest.NewRequest(tt.method, "/api/bulk-status", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")

			if tt.userID > 0 {
				session, _ := app.SessionStore.Get(req, "vulfixx-session")
				session.Values["user_id"] = tt.userID
				if tt.activeTeamID > 0 {
					session.Values["team_id"] = tt.activeTeamID
				}
				rr := httptest.NewRecorder()
				_ = session.Save(req, rr)

				req = httptest.NewRequest(tt.method, "/api/bulk-status", strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
				for _, c := range rr.Result().Cookies() {
					req.AddCookie(c)
				}
			}

			rr2 := httptest.NewRecorder()
			app.BulkUpdateCVEStatusHandler(rr2, req)

			if rr2.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.expectedStatus, rr2.Code)
			}

			bodyStr := rr2.Body.String()
			if !strings.Contains(bodyStr, tt.expectedJSON) {
				t.Errorf("%s: expected JSON body to contain %q, got %q", tt.name, tt.expectedJSON, bodyStr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("%s: unmet expectations: %v", tt.name, err)
			}
		})
	}
}
