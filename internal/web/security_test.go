package web

import (
	"cve-tracker/internal/db"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	app := &App{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("DefaultHeaders", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		app.SecurityHeadersMiddleware(next).ServeHTTP(rr, req)

		expectedHeaders := map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"X-XSS-Protection":          "1; mode=block",
		}

		for h, v := range expectedHeaders {
			if rr.Header().Get(h) != v {
				t.Errorf("expected header %s to be %s, got %s", h, v, rr.Header().Get(h))
			}
		}
		if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "default-src 'self'") {
			t.Errorf("CSP missing default-src 'self'")
		}
	})

	t.Run("CSPNonce", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		app.SecurityHeadersMiddleware(next).ServeHTTP(rr, req)

		csp := rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "'nonce-") {
			t.Errorf("CSP should contain a nonce")
		}
	})
}

func TestAdminMiddleware(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	handler := app.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Unauthenticated", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for unauthenticated user, got %d", rr.Code)
		}
	})

	t.Run("NonAdmin", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_admin FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(false))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for non-admin, got %d", rr.Code)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_admin FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})

	t.Run("SessionGetError", func(t *testing.T) {
		mockStore := &MockSessionStore{}
		originalStore := app.SessionStore
		app.SessionStore = mockStore
		defer func() { app.SessionStore = originalStore }()

		callCount := 0
		mockStore.GetFunc = func(r *http.Request, name string) (*sessions.Session, error) {
			callCount++
			if callCount == 1 {
				// GetUserID call
				s := sessions.NewSession(mockStore, name)
				s.Values["user_id"] = 1
				return s, nil
			}
			// AdminMiddleware call
			return nil, fmt.Errorf("session get error")
		}

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_admin FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(true))

		req, _ := http.NewRequest("GET", "/admin", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error for session get error, got %d", rr.Code)
		}
	})

	t.Run("SessionSaveError", func(t *testing.T) {
		mockStore := &MockSessionStore{
			SaveFunc: func(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
				return fmt.Errorf("session save error")
			},
		}
		originalStore := app.SessionStore
		app.SessionStore = mockStore
		defer func() { app.SessionStore = originalStore }()

		mockStore.GetFunc = func(r *http.Request, name string) (*sessions.Session, error) {
			s := sessions.NewSession(mockStore, name)
			s.Values["user_id"] = 1
			return s, nil
		}

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_admin FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(true))

		req, _ := http.NewRequest("GET", "/admin", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		// session.Save error only logs, doesn't return error response
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK despite session save error, got %d", rr.Code)
		}
	})

	t.Run("Admin_Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", nil)
		setSessionUser(t, app, req, 1, true)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_admin FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_admin"}).AddRow(true))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK for admin, got %d", rr.Code)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestAuthMiddleware(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	handler := app.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Unauthenticated", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect for unauthenticated user, got %d", rr.Code)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnError(pgx.ErrNoRows)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect for missing user, got %d", rr.Code)
		}
	})

	t.Run("Authenticated_Unverified", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(false, false, true))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for unverified user, got %d", rr.Code)
		}
	})

	t.Run("TOTP_Enabled_Not_Verified", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(true, true, true))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect for TOTP not verified, got %d", rr.Code)
		}
	})

	t.Run("TOTP_Enabled_Verified", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["totp_verified"] = true
		rr1 := httptest.NewRecorder()
		_ = session.Save(req, rr1)
		for _, c := range rr1.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(true, true, true))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK for TOTP verified, got %d", rr.Code)
		}
	})

	t.Run("Onboarding_Not_Completed_Protected_Path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(true, false, false))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect for incomplete onboarding, got %d", rr.Code)
		}
		if !strings.Contains(rr.Header().Get("Location"), "/settings") {
			t.Errorf("expected redirect to /settings, got %s", rr.Header().Get("Location"))
		}
	})

	t.Run("Onboarding_Not_Completed_Allowed_Path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/settings", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(true, false, false))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK for allowed path during onboarding, got %d", rr.Code)
		}
	})

	t.Run("Authenticated_Verified", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_email_verified", "is_totp_enabled", "onboarding_completed"}).AddRow(true, false, true))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK for verified user, got %d", rr.Code)
		}
	})
}

func TestDashboardNoErrorLeakOnMalformedQuery(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	// Malicious keyword that attempts to break out of string and run additional commands
	maliciousKeyword := "'; DROP TABLE users; --"

	v := url.Values{}
	v.Set("q", maliciousKeyword)
	req, _ := http.NewRequest("GET", "/dashboard?"+v.Encode(), nil)
	setSessionUser(t, app, req, 1, false)

	// 1. metricsQuery (consolidated)
	mock.ExpectQuery("(?is)SELECT.*total_cves.*").
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit", "prog", "sev_crit", "sev_high", "sev_med", "sev_low", "stat_active", "stat_prog", "stat_res", "stat_ign"}).
			AddRow(100, 10, 5, 2, 5, 1, 0, 0, 1, 0, 0, 0))

	// 2. query (CVE list)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id")).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
			AddRow(1, "CVE-1", "Desc", 5.0, "", false, time.Now(), time.Now(), "active", []string{}, "", 0.1, "", "", 0, 0, "", []byte(`{}`), "V", "P", []byte(`[]`), "P2"))

	// 5. cweQuery
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cwe_id, COALESCE(MAX(cwe_name), 'Unknown')")).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 1))

	// 6. RenderTemplate calls
	mock.ExpectQuery(regexp.QuoteMeta("SELECT onboarding_completed FROM users WHERE id = $1")).
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"onboarding_completed"}).AddRow(true))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1")).
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("(?is)SELECT t.id, t.name FROM teams t").
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Team1"))

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)

	body := rr.Body.String()
	badPhrases := []string{"syntax error", "unterminated string literal", "sql error"}
	for _, p := range badPhrases {
		if strings.Contains(strings.ToLower(body), p) {
			t.Errorf("Potential SQL injection leak detected in response body: %s", body)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
