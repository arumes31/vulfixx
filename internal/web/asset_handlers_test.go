package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestAssetsHandler(t *testing.T) {
	t.Run("GET_Unauthenticated", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/assets", nil)
		rr := httptest.NewRecorder()
		app.AssetsHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr.Code)
		}
	})

	t.Run("GET_Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		// Setup session
		req := httptest.NewRequest("GET", "/assets", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/assets", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery(regexp.QuoteMeta("SELECT a.id, a.name")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "type", "created_at", "keywords", "team_name"}).
				AddRow(1, "Asset 1", "server", time.Now(), []string{"test"}, "Team A"))

		// Teams query from RenderTemplate (called because user is logged in)
		mock.ExpectQuery(regexp.QuoteMeta("SELECT t.id, t.name FROM teams t JOIN team_members tm")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Test Team"))

		rr2 := httptest.NewRecorder()
		app.AssetsHandler(rr2, req)
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("POST", func(t *testing.T) {
		tests := []struct {
			name           string
			form           url.Values
			mockExpect     func(mock pgxmock.PgxPoolIface)
			expectedStatus int
			expectedBody   string
		}{
			{
				name: "Success_Private",
				form: url.Values{
					"name":     {"My Asset"},
					"type":     {"Server"},
					"keywords": {"prod, web"},
				},
				mockExpect: func(mock pgxmock.PgxPoolIface) {
					mock.ExpectBegin()
					mock.ExpectQuery("INSERT INTO assets").
						WithArgs(1, pgxmock.AnyArg(), "My Asset", "Server").
						WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(101))
					mock.ExpectExec("INSERT INTO asset_keywords").
						WithArgs(101, "prod").
						WillReturnResult(pgxmock.NewResult("INSERT", 1))
					mock.ExpectExec("INSERT INTO asset_keywords").
						WithArgs(101, "web").
						WillReturnResult(pgxmock.NewResult("INSERT", 1))
					mock.ExpectCommit()
					mock.ExpectExec("INSERT INTO user_activity_logs").
						WithArgs(1, "asset_registered", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
						WillReturnResult(pgxmock.NewResult("INSERT", 1))
				},
				expectedStatus: http.StatusFound,
				expectedBody:   "",
			},
			{
				name: "Success_Team",
				form: url.Values{
					"name":    {"Team Asset"},
					"type":    {"Cloud"},
					"team_id": {"10"},
				},
				mockExpect: func(mock pgxmock.PgxPoolIface) {
					mock.ExpectQuery("SELECT EXISTS").WithArgs(10, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
					mock.ExpectBegin()
					mock.ExpectQuery("INSERT INTO assets").
						WithArgs(1, pgxmock.AnyArg(), "Team Asset", "Cloud").
						WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(102))
					mock.ExpectCommit()
					mock.ExpectExec("INSERT INTO user_activity_logs").
						WithArgs(1, "asset_registered", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
						WillReturnResult(pgxmock.NewResult("INSERT", 1))
				},
				expectedStatus: http.StatusFound,
				expectedBody:   "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mock, _ := db.SetupTestDB()
				defer mock.Close()
				app := setupTestApp(t, mock)

				req := httptest.NewRequest("POST", "/assets", strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				setSessionUser(t, app, req, 1)

				tt.mockExpect(mock)

				rr := httptest.NewRecorder()
				app.AssetsHandler(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("expected %d, got %d", tt.expectedStatus, rr.Code)
				}
				if tt.expectedBody != "" && !strings.Contains(rr.Body.String(), tt.expectedBody) {
					t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rr.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("unmet expectations: %v", err)
				}
			})
		}
	})
}

func TestDeleteAssetHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		form := url.Values{"id": {"1"}}
		req := httptest.NewRequest("POST", "/assets/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, 1)

		mock.ExpectExec("DELETE FROM assets").
			WithArgs(1, 1).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(1, "asset_deleted", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
		app.DeleteAssetHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr.Code)
		}
	})
}
