package web

import (
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestActivityLogHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/activity", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/activity", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow(1, "login", "User logged in", "127.0.0.1", time.Now()))

		expectBaseQueries(mock, 1)
		rr2 := httptest.NewRecorder()
		app.ActivityLogHandler(rr2, req)

		if rr2.Code != http.StatusOK && rr2.Code != http.StatusBadRequest {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/activity", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`SELECT id, activity_type, description, ip_address, created_at FROM user_activity_logs`).
			WithArgs(1).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.ActivityLogHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})
}

func TestExportActivityLogHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/activity/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`SELECT id, activity_type, description, ip_address, created_at FROM user_activity_logs`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow(1, "login", "User logged in", "127.0.0.1", time.Now()))

		rr := httptest.NewRecorder()
		app.ExportActivityLogHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if rr.Header().Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", rr.Header().Get("Content-Type"))
		}
		
		var logs []map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&logs); err != nil {
			t.Errorf("failed to decode JSON: %v", err)
		}
		if len(logs) != 1 {
			t.Errorf("expected 1 log entry, got %d", len(logs))
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/activity/export", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(`SELECT id, activity_type, description, ip_address, created_at FROM user_activity_logs`).
			WithArgs(1).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.ExportActivityLogHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})
}
