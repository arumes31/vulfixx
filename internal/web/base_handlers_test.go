package web

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestIndexHandler(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("NotFound", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/non-existent-path-123", nil)
		rr := httptest.NewRecorder()
		app.IndexHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found, got %d", rr.Code)
		}
	})

	t.Run("Unauthenticated", func(t *testing.T) {
		// Populate cache to avoid DB hits for metrics
		statsCache.Lock()
		origStatsTotal := statsCache.total
		origStatsKevCount := statsCache.kevCount
		origStatsCritCount := statsCache.critCount
		origStatsSeverityCounts := statsCache.severityCounts
		origStatsTopCWEs := statsCache.topCWEs
		origStatsEpssDist := statsCache.epssDist
		t.Cleanup(func() {
			statsCache.Lock()
			statsCache.total = origStatsTotal
			statsCache.kevCount = origStatsKevCount
			statsCache.critCount = origStatsCritCount
			statsCache.severityCounts = origStatsSeverityCounts
			statsCache.topCWEs = origStatsTopCWEs
			statsCache.epssDist = origStatsEpssDist
			statsCache.Unlock()
		})
		statsCache.total = 100
		statsCache.kevCount = 10
		statsCache.critCount = 5
		statsCache.severityCounts = SeverityCounts{High: 1}
		statsCache.topCWEs = []CWEStat{{ID: "CWE-79", Name: "XSS", Count: 1}}
		statsCache.epssDist = []int{1, 0, 0, 0}
		statsCache.Unlock()

		// 1. Main query
		// Columns (21): id, cve_id, description, cvss_score, vector_string, cisa_kev, published_date, updated_date, status, references, epss_score, cwe_id, cwe_name, github_poc_count, greynoise_hits, greynoise_classification, osv_data, vendor, product, affected_products, priority
		mock.ExpectQuery(regexp.QuoteMeta("SELECT c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, c.published_date, c.updated_date, 'active' as status, COALESCE(c.\"references\", '{}'), COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0), COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'), COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority FROM cves c WHERE (1=1) ORDER BY c.published_date DESC NULLS LAST, c.id DESC LIMIT $1 OFFSET $2")).
			WithArgs(20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products", "priority"}).
				AddRow(1, "CVE-2024-0001", "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, 0.123, "CWE-79", "XSS", 1, 0, "", []byte("{}"), "", "", []byte("[]"), "P2"))

		// 2. Ransomware check for scanning results
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)")).WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "cisa_ransomware"}).AddRow(1, false))

		// 3. Trending CVEs query
		// Columns (20): id, cve_id, description, cvss_score, vector_string, cisa_kev, published_date, updated_date, status, references, epss_score, cwe_id, cwe_name, github_poc_count, greynoise_hits, greynoise_classification, osv_data, vendor, product, affected_products
		mock.ExpectQuery("SELECT.*c.id, c.cve_id.*FROM cves c.*ORDER BY c.github_poc_count DESC").WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "epss_score", "cwe_id", "cwe_name", "github_poc_count", "greynoise_hits", "greynoise_classification", "osv_data", "vendor", "product", "affected_products"}).
			AddRow(2, "CVE-2024-9999", "Trending", 9.8, "", true, time.Now(), time.Now(), "active", []string{}, 0.9, "CWE-89", "SQLi", 5, 0, "", []byte("{}"), "", "", []byte("[]")))

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		app.IndexHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		session, _ := app.SessionStore.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		app.IndexHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr2.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestGetClientIP(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("FromContext", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), clientIPKey, "1.2.3.4")
		req = req.WithContext(ctx)
		ip := app.GetClientIP(req)
		if ip != "1.2.3.4" {
			t.Errorf("expected 1.2.3.4, got %s", ip)
		}
	})

	t.Run("FromRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "5.6.7.8:1234"
		ip := app.GetClientIP(req)
		if ip != "5.6.7.8" {
			t.Errorf("expected 5.6.7.8, got %s", ip)
		}
	})

	t.Run("InvalidRemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "invalid-addr"
		ip := app.GetClientIP(req)
		if ip != "invalid-addr" {
			t.Errorf("expected invalid-addr, got %s", ip)
		}
	})
}

func TestLogActivity_Extended(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("SuccessWithLongIP", func(t *testing.T) {
		longIP := "2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra-garbage-that-makes-it-too-long"
		expectedIP := longIP[:45]

		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(1, "test", "desc", expectedIP, "agent", pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		app.LogActivity(context.Background(), 1, "test", "desc", longIP, "agent")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("SuccessWithPort", func(t *testing.T) {
		ipWithPort := "1.2.3.4:5678"
		expectedIP := "1.2.3.4"

		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(1, "test", "desc", expectedIP, "agent", pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		app.LogActivity(context.Background(), 1, "test", "desc", ipWithPort, "agent")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("DBError", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(context.DeadlineExceeded)

		// This should log the error and not panic
		app.LogActivity(context.Background(), 1, "test", "desc", "1.2.3.4", "agent")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestSendResponse(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	app := setupTestApp(t, mock)

	tests := []struct {
		name           string
		success        bool
		message        string
		redirect       string
		errMsg         string
		headers        map[string]string
		expectedStatus int
		expectedJSON   bool
		expectedBody   string
		expectedLoc    string
	}{
		{
			name:           "JSON success",
			success:        true,
			message:        "Success",
			headers:        map[string]string{"X-Requested-With": "XMLHttpRequest"},
			expectedStatus: http.StatusOK,
			expectedJSON:   true,
			expectedBody:   `{"message":"Success","success":true}`,
		},
		{
			name:           "JSON error unauthorized",
			success:        false,
			errMsg:         "Unauthorized access",
			headers:        map[string]string{"Accept": "application/json"},
			expectedStatus: http.StatusUnauthorized,
			expectedJSON:   true,
			expectedBody:   `{"error":"Unauthorized access","success":false}`,
		},
		{
			name:           "JSON error forbidden",
			success:        false,
			errMsg:         "Forbidden action",
			headers:        map[string]string{"Accept": "application/json"},
			expectedStatus: http.StatusForbidden,
			expectedJSON:   true,
		},
		{
			name:           "JSON error not found",
			success:        false,
			errMsg:         "Resource not found",
			headers:        map[string]string{"Accept": "application/json"},
			expectedStatus: http.StatusNotFound,
			expectedJSON:   true,
		},
		{
			name:           "JSON error internal",
			success:        false,
			errMsg:         "Internal server error",
			headers:        map[string]string{"Accept": "application/json"},
			expectedStatus: http.StatusInternalServerError,
			expectedJSON:   true,
		},
		{
			name:           "JSON error method not allowed",
			success:        false,
			errMsg:         "Method not allowed",
			headers:        map[string]string{"Accept": "application/json"},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedJSON:   true,
		},
		{
			name:           "JSON error conflict",
			success:        false,
			errMsg:         "Conflict detected",
			headers:        map[string]string{"Accept": "application/json"},
			expectedStatus: http.StatusConflict,
			expectedJSON:   true,
		},
		{
			name:           "Redirect success default",
			success:        true,
			expectedStatus: http.StatusFound,
			expectedLoc:    "/",
		},
		{
			name:           "Redirect success custom",
			success:        true,
			redirect:       "/dashboard",
			expectedStatus: http.StatusFound,
			expectedLoc:    "/dashboard",
		},
		{
			name:           "HTML error",
			success:        false,
			errMsg:         "Bad request error",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Bad request error\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()

			app.SendResponse(rr, req, tt.success, tt.message, tt.redirect, tt.errMsg)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedJSON {
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", contentType)
				}
				var resp map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal JSON body: %v", err)
				}
				if tt.expectedBody != "" {
					var expected map[string]interface{}
					_ = json.Unmarshal([]byte(tt.expectedBody), &expected)
					for k, v := range expected {
						if resp[k] != v {
							t.Errorf("expected key %s to be %v, got %v", k, v, resp[k])
						}
					}
				}
			} else if tt.expectedLoc != "" {
				loc := rr.Header().Get("Location")
				if loc != tt.expectedLoc {
					t.Errorf("expected Location %s, got %s", tt.expectedLoc, loc)
				}
			} else if tt.expectedBody != "" {
				if rr.Body.String() != tt.expectedBody {
					t.Errorf("expected body %q, got %q", tt.expectedBody, rr.Body.String())
				}
			}
		})
	}
}

func TestRenderTemplate(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("Unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		// Render a simple template
		app.RenderTemplate(rr, req, "login.html", nil)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		userID := 1
		req := httptest.NewRequest("GET", "/", nil)
		setSessionUser(t, app, req, userID, false)

		// Expectations for RenderTemplate queries
		expectBaseQueries(mock, userID)

		rr := httptest.NewRecorder()
		app.RenderTemplate(rr, req, "dashboard.html", nil)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("DataTypes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		t.Run("Map", func(t *testing.T) {
			rr := httptest.NewRecorder()
			app.RenderTemplate(rr, req, "message.html", map[string]interface{}{"Message": "Test Map"})
			if !strings.Contains(rr.Body.String(), "Test Map") {
				t.Error("template did not contain map data")
			}
		})

		t.Run("Struct", func(t *testing.T) {
			rr := httptest.NewRecorder()
			type TestData struct {
				Message string
			}
			app.RenderTemplate(rr, req, "message.html", TestData{Message: "Test Struct"})
			if !strings.Contains(rr.Body.String(), "Test Struct") {
				t.Error("template did not contain struct data")
			}
		})

		t.Run("Pointer", func(t *testing.T) {
			rr := httptest.NewRecorder()
			type TestData struct {
				Message string
			}
			app.RenderTemplate(rr, req, "message.html", &TestData{Message: "Test Pointer"})
			if !strings.Contains(rr.Body.String(), "Test Pointer") {
				t.Error("template did not contain pointer data")
			}
		})
	})

	t.Run("TemplateNotFound", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		app.RenderTemplate(rr, req, "non-existent.html", nil)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 Internal Server Error, got %d", rr.Code)
		}
	})
}
