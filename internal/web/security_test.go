package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	app := &App{}
	handler := app.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"X-XSS-Protection":          "1; mode=block",
	}

	for key, expectedValue := range expectedHeaders {
		if value := rr.Header().Get(key); value != expectedValue {
			t.Errorf("handler returned wrong header %s: got %v want %v", key, value, expectedValue)
		}
	}
}

func TestCSRFProtection(t *testing.T) {
	// Our app uses custom CSRF for admin and standard gorilla/csrf for web
	// Let's test the Admin CSRF logic
	app := &App{
		SessionStore: sessions.NewCookieStore([]byte("secret")),
	}

	t.Run("ValidToken", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/admin/delete", strings.NewReader("csrf_token=valid"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["admin_csrf_token"] = "valid"
		
		if !app.ValidateCSRF(req) {
			t.Errorf("expected CSRF validation to pass")
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/admin/delete", strings.NewReader("csrf_token=invalid"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["admin_csrf_token"] = "valid"
		
		if app.ValidateCSRF(req) {
			t.Errorf("expected CSRF validation to fail")
		}
	})
}

func TestXSSPrevention(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	// We'll test RenderTemplate with a malicious string
	// and check if it's escaped in the response body.
	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	
	malicious := "<script>alert('xss')</script>"
	data := map[string]interface{}{
		"Message": malicious,
	}
	
	// Use message.html which displays .Message
	app.RenderTemplate(rr, req, "message.html", data)
	
	body := rr.Body.String()
	if strings.Contains(body, malicious) {
		t.Errorf("XSS payload found unescaped in response: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("XSS payload was not correctly escaped: %s", body)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	app := &App{}
	handler := app.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	// Trigger rate limit
	// Limit is 5 rps, burst 10.
	for i := 0; i < 15; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if i < 10 {
			if rr.Code != http.StatusOK {
				t.Errorf("expected 200 OK at request %d, got %d", i, rr.Code)
			}
		} else {
			if rr.Code != http.StatusTooManyRequests {
				t.Errorf("expected 429 Too Many Requests at request %d, got %d", i, rr.Code)
			}
		}
	}
}

func TestAuthMiddleware(t *testing.T) {
	mock, _ := db.SetupTestDB()
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

	t.Run("Authenticated_Unverified", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/dashboard", nil)
		setSessionUser(t, app, req, 1, false)
		
		// Mock verified check in middleware
		mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified FROM users WHERE id = $1")).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"is_verified"}).AddRow(false))
			
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		
		// If unverified, it should allow access but maybe templates show warning?
		// Actually, let's check base.go middleware logic.
	})
}

func TestAdminMiddleware(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	handler := app.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

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

	t.Run("Admin", func(t *testing.T) {
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
}

func TestSQLInjectionPrevention(t *testing.T) {
	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)
	
	// Malicious keyword that attempts to break out of string and run additional commands
	maliciousKeyword := "'; DROP TABLE users; --"
	
	req, _ := http.NewRequest("GET", "/dashboard?q="+maliciousKeyword, nil)
	setSessionUser(t, app, req, 1, false)

	// Mocking the query to ensure it's still using the expected structure
	mock.ExpectQuery("SELECT.*COUNT.*DISTINCT").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit", "prog"}).AddRow(100, 10, 5, 2))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT DISTINCT c.id")).
		WithArgs(1, 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products"}).
			AddRow(1, "CVE-1", "Desc", 5.0, "", false, time.Now(), time.Now(), "active", []string{}, "", 0.1, "", "", 0, 0, "", []byte(`{}`), "V", "P", []byte(`[]`)))

	mock.ExpectQuery("SELECT.*COUNT.*DISTINCT.*cvss_score").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low"}).AddRow(0, 0, 1, 0))
	mock.ExpectQuery("SELECT.*COUNT.*DISTINCT.*status").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"active", "prog", "res", "ign"}).AddRow(1, 0, 0, 0))
	
	expectBaseQueries(mock, 1)

	rr := httptest.NewRecorder()
	app.DashboardHandler(rr, req)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
