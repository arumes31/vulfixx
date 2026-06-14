package web

import (
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
)

type failingSessionStore struct {
	sessions.Store
}

func (s *failingSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	session, err := s.Store.Get(r, name)
	if session != nil {
		newSession := sessions.NewSession(s, name)
		newSession.Values = session.Values
		newSession.Options = session.Options
		newSession.IsNew = session.IsNew
		return newSession, err
	}
	return session, err
}

func (s *failingSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session, err := s.Store.New(r, name)
	if session != nil {
		newSession := sessions.NewSession(s, name)
		newSession.Values = session.Values
		newSession.Options = session.Options
		newSession.IsNew = session.IsNew
		return newSession, err
	}
	return session, err
}

func (s *failingSessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	return fmt.Errorf("session save error")
}

func TestDeleteAccountHandler(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("POST", "/settings/delete", nil)
		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("InvalidMethod", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		req := httptest.NewRequest("GET", "/settings/delete", nil)
		setSessionUser(t, app, req, 1, false)
		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/settings" {
			t.Errorf("expected redirect to /settings, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		app := setupTestApp(t, mock)

		userID := 1
		req := httptest.NewRequest("POST", "/settings/delete", nil)
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("not found"))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"password": {"wrong"}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		hashedPassword, _ := auth.HashPassword("correct")
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid password") {
			t.Errorf("expected 'Invalid password' error in body")
		}
	})

	t.Run("DeleteDBError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"password": {"password"}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword("password")

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))

		mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		userID := 1
		password := "correct_password"
		form := url.Values{"password": {password}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		hashedPassword, _ := auth.HashPassword(password)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))

		mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/register" {
			t.Errorf("expected redirect to /register, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}

		if !slices.ContainsFunc(rr.Result().Cookies(), func(c *http.Cookie) bool {
			return c.Name == "vulfixx-session" && c.MaxAge < 0
		}) {
			t.Errorf("expected session cookie to be cleared (MaxAge < 0)")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("SessionSaveError", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		userID := 1
		password := "correct_password"
		form := url.Values{"password": {password}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		// Inject failing session store after session is set
		app.SessionStore = &failingSessionStore{app.SessionStore}

		hashedPassword, _ := auth.HashPassword(password)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", string(hashedPassword), true, false, "", false))

		mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		// Handler still redirects even if session save fails (it only logs)
		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/register" {
			t.Errorf("expected redirect to /register, got %d and location %s", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		oldPool := db.Pool
		db.Pool = mock
		defer func() { db.Pool = oldPool }()

		app := setupTestApp(t, mock)

		userID := 1
		form := url.Values{"password": {""}}
		req := httptest.NewRequest("POST", "/settings/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setSessionUser(t, app, req, userID, false)

		mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

		// auth.Login will fail because password is empty
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
			WithArgs("user@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(userID, "user@example.com", "somehash", true, false, "", false))

		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.DeleteAccountHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid password") {
			t.Errorf("expected 'Invalid password' error in body")
		}
	})
}
