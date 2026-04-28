package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestCVEDetailHandler_Extra(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-2023-1234"
		mock.ExpectQuery(`SELECT id, cve_id, description, cvss_score, vector_string, cisa_kev, published_date, updated_date, 'active' as status, references, epss_score, cwe_id, cwe_name, github_poc_count FROM cves WHERE cve_id = \$1`).
			WithArgs(cveID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count"}).
				AddRow(1, cveID, "Test description", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, time.Now(), time.Now(), "active", "[]", 0.5, "CWE-79", "XSS", 10))

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": cveID})
		rr := httptest.NewRecorder()

		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-NOT-FOUND"
		mock.ExpectQuery(`SELECT .* FROM cves WHERE cve_id = \$1`).
			WithArgs(cveID).
			WillReturnError(pgx.ErrNoRows)

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": cveID})
		rr := httptest.NewRecorder()

		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found, got %d", rr.Code)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		cveID := "CVE-ERROR"
		mock.ExpectQuery(`SELECT .* FROM cves WHERE cve_id = \$1`).
			WithArgs(cveID).
			WillReturnError(fmt.Errorf("db error"))

		req, _ := http.NewRequest("GET", "/cve/"+cveID, nil)
		req = mux.SetURLVars(req, map[string]string{"id": cveID})
		rr := httptest.NewRecorder()

		app.CVEDetailHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})
}

func TestExportCVEsHandler_Extra(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1)

		mock.ExpectQuery(`SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date"}).
				AddRow("CVE-2023-0001", "Desc 1", 9.8, true, time.Now()).
				AddRow("CVE-2023-0002", "Desc 2", 5.0, false, time.Now()))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if rr.Header().Get("Content-Type") != "text/csv" {
			t.Errorf("expected text/csv, got %s", rr.Header().Get("Content-Type"))
		}
		if !strings.Contains(rr.Body.String(), "CVE-2023-0001") {
			t.Errorf("expected body to contain CVE-2023-0001")
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1)

		mock.ExpectQuery(`SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnError(fmt.Errorf("db error"))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})

	t.Run("ScanError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/export", nil)
		setSessionUser(t, app, req, 1)

		// Return a row that will fail to scan (e.g., wrong type)
		mock.ExpectQuery(`SELECT DISTINCT c.cve_id`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id", "description", "cvss_score", "cisa_kev", "published_date"}).
				AddRow("CVE-2023-0001", "Desc 1", "not-a-float", true, time.Now()))

		rr := httptest.NewRecorder()
		app.ExportCVEsHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK (even with scan errors), got %d", rr.Code)
		}
	})
}

func TestActivityLogHandler_Extra(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/activity", nil)
		setSessionUser(t, app, req, 1)

		mock.ExpectQuery(`SELECT id, activity_type, description, ip_address, created_at FROM user_activity_logs`).
			WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow(1, "login", "User logged in", "127.0.0.1", time.Now()))

		// RenderTemplate calls: Fetch user's teams
		expectBaseQueries(mock, 1)

		rr := httptest.NewRecorder()
		app.ActivityLogHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("DatabaseError", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/activity", nil)
		setSessionUser(t, app, req, 1)

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

func TestExportActivityLogHandler_Extra(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		req, _ := http.NewRequest("GET", "/activity/export", nil)
		setSessionUser(t, app, req, 1)

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
		setSessionUser(t, app, req, 1)

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

func TestSwitchTeamHandler_Extra(t *testing.T) {
	t.Run("ExternalReferer", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		form := url.Values{"team_id": {"10"}}
		req := httptest.NewRequest("POST", "/teams/switch", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "https://malicious.com")
		setSessionUser(t, app, req, 1)

		mock.ExpectQuery("SELECT EXISTS").
			WithArgs(10, 1).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

		rr := httptest.NewRecorder()
		app.SwitchTeamHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
		if rr.Header().Get("Location") != "/dashboard" {
			t.Errorf("expected redirect to /dashboard for external referer, got %s", rr.Header().Get("Location"))
		}
	})
	
	t.Run("InvalidReferer", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		form := url.Values{"team_id": {"10"}}
		req := httptest.NewRequest("POST", "/teams/switch", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "::invalid-url::")
		setSessionUser(t, app, req, 1)

		mock.ExpectQuery("SELECT EXISTS").
			WithArgs(10, 1).
			WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))

		rr := httptest.NewRecorder()
		app.SwitchTeamHandler(rr, req)

		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 Found, got %d", rr.Code)
		}
		if rr.Header().Get("Location") != "/dashboard" {
			t.Errorf("expected redirect to /dashboard for invalid referer, got %s", rr.Header().Get("Location"))
		}
	})
}

func TestMiddlewares_Coverage(t *testing.T) {
	t.Run("SecurityHeaders", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.SecurityHeadersMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		headers := []string{
			"X-Content-Type-Options",
			"X-Frame-Options",
			"Strict-Transport-Security",
			"Referrer-Policy",
			"X-XSS-Protection",
			"Content-Security-Policy",
		}

		for _, h := range headers {
			if rr.Header().Get(h) == "" {
				t.Errorf("expected header %s to be set", h)
			}
		}
	})

	t.Run("ProxyMiddleware_Cloudflare", func(t *testing.T) {
		os.Setenv("ENABLE_CLOUDFLARE_PROXY", "true")
		defer os.Unsetenv("ENABLE_CLOUDFLARE_PROXY")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Context().Value(clientIPKey).(string)
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("CF-Connecting-IP", "1.2.3.4")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "1.2.3.4" {
			t.Errorf("expected client IP 1.2.3.4, got %s", capturedIP)
		}
	})

	t.Run("ProxyMiddleware_TrustedProxy", func(t *testing.T) {
		os.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
		defer os.Unsetenv("TRUSTED_PROXIES")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Context().Value(clientIPKey).(string)
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.1")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "5.6.7.8" {
			t.Errorf("expected client IP 5.6.7.8, got %s", capturedIP)
		}
	})
	
	t.Run("ProxyMiddleware_UntrustedProxy", func(t *testing.T) {
		os.Setenv("TRUSTED_PROXIES", "127.0.0.1")
		defer os.Unsetenv("TRUSTED_PROXIES")

		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		var capturedIP string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Context().Value(clientIPKey).(string)
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.ProxyMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.1.1.1:12345"
		req.Header.Set("X-Forwarded-For", "5.6.7.8")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		if capturedIP != "1.1.1.1" {
			t.Errorf("expected client IP 1.1.1.1 (RemoteAddr), got %s", capturedIP)
		}
	})

	t.Run("RateLimitMiddleware_Trigger", func(t *testing.T) {
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		app := setupTestApp(t, mock)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := app.RateLimitMiddleware(next)
		req, _ := http.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		// Limiter has burst of 10.
		for i := 0; i < 10; i++ {
			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("request %d should have been allowed", i)
			}
		}

		// 11th request should be rate limited
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429 Too Many Requests, got %d", rr.Code)
		}
	})
}
