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

		mock.ExpectQuery("SELECT a.id, a.name, a.type, a.created_at").
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "type", "created_at", "keywords", "team_name"}).
				AddRow(1, "Server 1", "Server", time.Now(), []string{"prod"}, "Team A"))

		// RenderTemplate expectations
		mock.ExpectQuery("SELECT t.id, t.name").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Team A"))

		req := httptest.NewRequest("GET", "/assets", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/assets", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

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
						WithArgs(1, "asset_registered", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
						WillReturnResult(pgxmock.NewResult("INSERT", 1))
				},
				expectedStatus: http.StatusOK,
				expectedBody:   "Asset registered successfully",
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
						WithArgs(1, "asset_registered", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
						WillReturnResult(pgxmock.NewResult("INSERT", 1))
				},
				expectedStatus: http.StatusOK,
				expectedBody:   "Asset registered successfully",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mock, _ := db.SetupTestDB()
				defer mock.Close()
				app := setupTestApp(t, mock)
				tt.mockExpect(mock)

				req := httptest.NewRequest("POST", "/assets", strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Accept", "application/json")
				session, _ := app.SessionStore.Get(req, "vulfixx-session")
				session.Values["user_id"] = 1
				rr := httptest.NewRecorder()
				_ = session.Save(req, rr)

				req = httptest.NewRequest("POST", "/assets", strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Accept", "application/json")
				for _, c := range rr.Result().Cookies() {
					req.AddCookie(c)
				}

				rr2 := httptest.NewRecorder()
				app.AssetsHandler(rr2, req)

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
	})
}

func TestDeleteAssetHandler(t *testing.T) {
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
			name:   "Success",
			method: "POST",
			form:   url.Values{"id": {"101"}},
			userID: 1,
			mockExpect: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("DELETE FROM assets").
					WithArgs(101, 1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
				mock.ExpectExec("INSERT INTO user_activity_logs").
					WithArgs(1, "asset_deleted", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Asset removed successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, _ := db.SetupTestDB()
			defer mock.Close()
			app := setupTestApp(t, mock)
			tt.mockExpect(mock)

			req := httptest.NewRequest(tt.method, "/assets/delete", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			if tt.userID != 0 {
				session, _ := app.SessionStore.Get(req, "vulfixx-session")
				session.Values["user_id"] = tt.userID
				rr := httptest.NewRecorder()
				_ = session.Save(req, rr)

				req = httptest.NewRequest(tt.method, "/assets/delete", strings.NewReader(tt.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Accept", "application/json")
				for _, c := range rr.Result().Cookies() {
					req.AddCookie(c)
				}
			}

			rr2 := httptest.NewRecorder()
			app.DeleteAssetHandler(rr2, req)

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

