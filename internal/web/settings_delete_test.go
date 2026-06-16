package web

import (
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	tests := []struct {
		name               string
		method             string
		authenticated      bool
		userID             int
		form               url.Values
		injectFailingStore bool
		setupMocks         func(mock pgxmock.PgxPoolIface)
		expectedCode       int
		expectedLocation   string
		expectedBody       string
		checkCookieCleared bool
	}{
		{
			name:             "Unauthenticated",
			method:           "POST",
			authenticated:    false,
			expectedCode:     http.StatusFound,
			expectedLocation: "/login",
		},
		{
			name:             "InvalidMethod",
			method:           "GET",
			authenticated:    true,
			userID:           1,
			expectedCode:     http.StatusFound,
			expectedLocation: "/settings",
		},
		{
			name:          "UserNotFound",
			method:        "POST",
			authenticated: true,
			userID:        1,
			setupMocks: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnError(fmt.Errorf("not found"))
			},
			expectedCode:     http.StatusFound,
			expectedLocation: "/login",
		},
		{
			name:          "InvalidPassword",
			method:        "POST",
			authenticated: true,
			userID:        1,
			form:          url.Values{"password": {"wrong"}},
			setupMocks: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

				hashedPassword, _ := auth.HashPassword("correct")
				mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
					WithArgs("user@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
						AddRow(1, "user@example.com", string(hashedPassword), true, false, "", false))

				expectBaseQueries(mock, 1)
			},
			expectedCode: http.StatusOK,
			expectedBody: "Invalid password",
		},
		{
			name:          "DeleteDBError",
			method:        "POST",
			authenticated: true,
			userID:        1,
			form:          url.Values{"password": {"password"}},
			setupMocks: func(mock pgxmock.PgxPoolIface) {
				hashedPassword, _ := auth.HashPassword("password")

				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

				mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
					WithArgs("user@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
						AddRow(1, "user@example.com", string(hashedPassword), true, false, "", false))

				mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnError(fmt.Errorf("db error"))
			},
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:          "Success",
			method:        "POST",
			authenticated: true,
			userID:        1,
			form:          url.Values{"password": {"correct_password"}},
			setupMocks: func(mock pgxmock.PgxPoolIface) {
				hashedPassword, _ := auth.HashPassword("correct_password")

				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

				mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
					WithArgs("user@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
						AddRow(1, "user@example.com", string(hashedPassword), true, false, "", false))

				mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
			},
			expectedCode:       http.StatusFound,
			expectedLocation:   "/register",
			checkCookieCleared: true,
		},
		{
			name:               "SessionSaveError",
			method:             "POST",
			authenticated:      true,
			userID:             1,
			form:               url.Values{"password": {"correct_password"}},
			injectFailingStore: true,
			setupMocks: func(mock pgxmock.PgxPoolIface) {
				hashedPassword, _ := auth.HashPassword("correct_password")

				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

				mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
					WithArgs("user@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
						AddRow(1, "user@example.com", string(hashedPassword), true, false, "", false))

				mock.ExpectExec("DELETE FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
			},
			expectedCode:     http.StatusFound,
			expectedLocation: "/register",
		},
		{
			name:          "EmptyPassword",
			method:        "POST",
			authenticated: true,
			userID:        1,
			form:          url.Values{"password": {""}},
			setupMocks: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

				mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
					WithArgs("user@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
						AddRow(1, "user@example.com", "somehash", true, false, "", false))

				expectBaseQueries(mock, 1)
			},
			expectedCode: http.StatusOK,
			expectedBody: "Invalid password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("failed to create mock pool: %v", err)
			}
			defer mock.Close()

			oldPool := db.Pool
			db.Pool = mock
			defer func() { db.Pool = oldPool }()

			app := setupTestApp(t, mock)

			if tt.setupMocks != nil {
				tt.setupMocks(mock)
			}

			var body io.Reader
			if tt.form != nil {
				body = strings.NewReader(tt.form.Encode())
			}
			req := httptest.NewRequest(tt.method, "/settings/delete", body)
			if tt.form != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			if tt.authenticated {
				setSessionUser(t, app, req, tt.userID, false)
			}

			if tt.injectFailingStore {
				app.SessionStore = &failingSessionStore{app.SessionStore}
			}

			rr := httptest.NewRecorder()
			app.DeleteAccountHandler(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, rr.Code)
			}

			if tt.expectedLocation != "" {
				loc := rr.Header().Get("Location")
				if loc != tt.expectedLocation {
					t.Errorf("expected location %s, got %s", tt.expectedLocation, loc)
				}
			}

			if tt.expectedBody != "" {
				if !strings.Contains(rr.Body.String(), tt.expectedBody) {
					t.Errorf("expected body to contain %q, got %q", tt.expectedBody, rr.Body.String())
				}
			}

			if tt.checkCookieCleared {
				found := false
				for _, cookie := range rr.Result().Cookies() {
					if cookie.Name == "vulfixx-session" && cookie.MaxAge < 0 {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected session cookie to be cleared (MaxAge < 0)")
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}
