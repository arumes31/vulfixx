package web

import (
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"fmt"
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
		name                 string
		method               string
		isAuthenticated      bool
		userID               int
		formPassword         string
		injectFailingSession bool
		mockSetup            func(mock pgxmock.PgxPoolIface)
		expectedStatus       int
		expectedLocation     string
		expectedBodyContains string
		expectSessionCleared bool
	}{
		{
			name:             "Unauthenticated",
			method:           "POST",
			isAuthenticated:  false,
			expectedStatus:   http.StatusFound,
			expectedLocation: "/login",
		},
		{
			name:             "InvalidMethod",
			method:           "GET",
			isAuthenticated:  true,
			userID:           1,
			expectedStatus:   http.StatusFound,
			expectedLocation: "/settings",
		},
		{
			name:            "UserNotFound",
			method:          "POST",
			isAuthenticated: true,
			userID:          1,
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnError(fmt.Errorf("not found"))
			},
			expectedStatus:   http.StatusFound,
			expectedLocation: "/login",
		},
		{
			name:            "InvalidPassword",
			method:          "POST",
			isAuthenticated: true,
			userID:          1,
			formPassword:    "wrong",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
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
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "Invalid password",
		},
		{
			name:            "DeleteDBError",
			method:          "POST",
			isAuthenticated: true,
			userID:          1,
			formPassword:    "password",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
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
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:            "Success",
			method:          "POST",
			isAuthenticated: true,
			userID:          1,
			formPassword:    "correct_password",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
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
			expectedStatus:       http.StatusFound,
			expectedLocation:     "/register",
			expectSessionCleared: true,
		},
		{
			name:                 "SessionSaveError",
			method:               "POST",
			isAuthenticated:      true,
			userID:               1,
			formPassword:         "correct_password",
			injectFailingSession: true,
			mockSetup: func(mock pgxmock.PgxPoolIface) {
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
			expectedStatus:   http.StatusFound,
			expectedLocation: "/register",
		},
		{
			name:            "EmptyPassword",
			method:          "POST",
			isAuthenticated: true,
			userID:          1,
			formPassword:    "",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery("SELECT email FROM users WHERE id = \\$1").
					WithArgs(1).
					WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("user@example.com"))

				// auth.Login will fail because password is empty
				mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE\\(totp_secret, ''\\), is_admin FROM users WHERE email = \\$1").
					WithArgs("user@example.com").
					WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
						AddRow(1, "user@example.com", "somehash", true, false, "", false))

				expectBaseQueries(mock, 1)
			},
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "Invalid password",
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

			if tt.mockSetup != nil {
				tt.mockSetup(mock)
			}

			var req *http.Request
			if tt.formPassword != "" || tt.method == "POST" {
				form := url.Values{}
				if tt.formPassword != "" || tt.name == "EmptyPassword" {
					form.Set("password", tt.formPassword)
				}
				req = httptest.NewRequest(tt.method, "/settings/delete", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(tt.method, "/settings/delete", nil)
			}

			if tt.isAuthenticated {
				setSessionUser(t, app, req, tt.userID, false)
			}

			if tt.injectFailingSession {
				app.SessionStore = &failingSessionStore{app.SessionStore}
			}

			rr := httptest.NewRecorder()
			app.DeleteAccountHandler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedLocation != "" {
				loc := rr.Header().Get("Location")
				if loc != tt.expectedLocation {
					t.Errorf("expected redirect to %s, got %s", tt.expectedLocation, loc)
				}
			}

			if tt.expectedBodyContains != "" {
				if !strings.Contains(rr.Body.String(), tt.expectedBodyContains) {
					t.Errorf("expected body to contain %q, but it didn't", tt.expectedBodyContains)
				}
			}

			if tt.expectSessionCleared {
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
