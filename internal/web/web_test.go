package web

import (
	"bytes"
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/pashagolub/pgxmock/v3"
	"golang.org/x/crypto/bcrypt"
)

func TestWebEndpointsCoverage(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION") == "true" {
		t.Skip("skipping integration test (SKIP_INTEGRATION=true)")
	}

	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_USER", "cveuser")
	t.Setenv("DB_PASSWORD", "cvepass")
	t.Setenv("DB_NAME", "cvetracker")
	t.Setenv("REDIS_URL", "localhost:6379")
	t.Setenv("SESSION_KEY", "supersecretkey")
	t.Setenv("CSRF_KEY", "0123456789abcdef0123456789abcdef")

	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	mock.MatchExpectationsInOrder(true)


	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	InitSession()

	// Need to be at project root or templates/ won't load
	origWD, wdErr := os.Getwd()
	if wdErr != nil {
		t.Fatalf("Failed to get working directory: %v", wdErr)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWD); err != nil {
			t.Errorf("Failed to restore working directory: %v", err)
		}
	})
	InitTemplatesWithFuncs()

	// Setup a router
	r := mux.NewRouter()
	r.Use(ProxyMiddleware)
	r.HandleFunc("/", IndexHandler).Methods("GET")
	r.HandleFunc("/feed", RSSFeedHandler).Methods("GET")
	r.Handle("/login", RateLimitMiddleware(http.HandlerFunc(LoginHandler))).Methods("GET", "POST")
	r.Handle("/register", RateLimitMiddleware(http.HandlerFunc(RegisterHandler))).Methods("GET", "POST")
	r.HandleFunc("/verify-email", VerifyEmailHandler).Methods("GET")
	r.HandleFunc("/confirm-email-change", ConfirmEmailChangeHandler).Methods("GET")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")

	protected := r.PathPrefix("").Subrouter()
	protected.Use(AuthMiddleware)
	protected.HandleFunc("/dashboard", DashboardHandler).Methods("GET")
	protected.HandleFunc("/api/status", UpdateCVEStatusHandler).Methods("POST")
	protected.HandleFunc("/api/status/bulk", BulkUpdateCVEStatusHandler).Methods("POST")
	protected.HandleFunc("/subscriptions", SubscriptionsHandler).Methods("GET", "POST")
	protected.HandleFunc("/subscriptions/delete", DeleteSubscriptionHandler).Methods("POST")
	protected.HandleFunc("/export", ExportCVEsHandler).Methods("GET")
	protected.HandleFunc("/activity", ActivityLogHandler).Methods("GET")
	protected.HandleFunc("/activity/export", ExportActivityLogHandler).Methods("GET")
	protected.HandleFunc("/alerts", AlertHistoryHandler).Methods("GET")
	protected.HandleFunc("/settings", SettingsHandler).Methods("GET")
	protected.HandleFunc("/settings/totp/generate", GenerateTOTPHandler).Methods("POST")
	protected.Handle("/settings/totp/verify", RateLimitMiddleware(http.HandlerFunc(VerifyTOTPHandler))).Methods("POST")
	protected.HandleFunc("/settings/password", ChangePasswordHandler).Methods("POST")
	protected.HandleFunc("/settings/email", ChangeEmailHandler).Methods("POST")
	protected.Handle("/settings/delete", RateLimitMiddleware(http.HandlerFunc(DeleteAccountHandler))).Methods("POST")

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Seed user expectations
	mock.ExpectExec("DELETE FROM users").WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec("DELETE FROM cves").WillReturnResult(pgxmock.NewResult("DELETE", 0))
	mock.ExpectExec("INSERT INTO cves").WillReturnResult(pgxmock.NewResult("INSERT", 3))

	// Register expectations
	mock.ExpectExec("INSERT INTO users").
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	
	// Seed user
	ctx := context.Background()
	_, _ = db.Pool.Exec(ctx, "DELETE FROM users WHERE email IN ('web_test2@example.com', 'new_web_test@example.com')")
	_, _ = db.Pool.Exec(ctx, "DELETE FROM cves WHERE id IN (1, 2, 3)")
	_, _ = db.Pool.Exec(ctx, `INSERT INTO cves (id, cve_id, description, cvss_score, published_date) VALUES 
		(1, 'CVE-2024-0001', 'Test CVE 1', 7.5, '2024-01-01'),
		(2, 'CVE-2024-0002', 'Test CVE 2', 8.5, '2024-01-02'),
		(3, 'CVE-2024-0003', 'Test CVE 3', 9.5, '2024-01-03')`)

	// Create a real user using Register
	form := url.Values{}
	form.Add("email", "web_test2@example.com")
	form.Add("password", "password123")
	reqReg, _ := http.NewRequest("POST", ts.URL+"/register", strings.NewReader(form.Encode()))
	reqReg.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resReg, err := client.Do(reqReg)
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}
	if resReg.StatusCode != http.StatusFound && resReg.StatusCode != http.StatusOK {
		t.Fatalf("Register failed with status %d", resReg.StatusCode)
	}
	_ = resReg.Body.Close()

	// Verify expectations
	mock.ExpectExec("UPDATE users SET is_email_verified = TRUE").
		WithArgs("web_test2@example.com").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectQuery("SELECT id FROM users").WithArgs("web_test2@example.com").
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

	// Login expectations
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	mock.ExpectQuery("SELECT id, email, password_hash").WithArgs("web_test2@example.com").
		WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
			AddRow(1, "web_test2@example.com", string(hashedPassword), true, false, "", false))

	// Verify email manually
	_, _ = db.Pool.Exec(ctx, "UPDATE users SET is_email_verified = TRUE WHERE email = $1", "web_test2@example.com")
	var userID int
	if err := db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", "web_test2@example.com").Scan(&userID); err != nil {
		t.Fatalf("Failed to scan user ID: %v", err)
	}

	// Login to get session cookie
	loginForm := url.Values{}
	loginForm.Add("email", "web_test2@example.com")
	loginForm.Add("password", "password123")
	reqLog, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(loginForm.Encode()))
	reqLog.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resLog, err := client.Do(reqLog)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	if resLog.StatusCode != http.StatusFound && resLog.StatusCode != http.StatusOK {
		t.Fatalf("Login failed with status %d", resLog.StatusCode)
	}
	_ = resLog.Body.Close()

	var sessionCookie *http.Cookie
	for _, cookie := range resLog.Cookies() {
		if cookie.Name == "session-name" {
			sessionCookie = cookie
			break
		}
	}

	doAuthReq := func(method, path string, body []byte, extraMocks func(), expectedCodes ...int) *http.Response {
		isPublic := path == "/" || strings.HasPrefix(path, "/feed") || path == "/login" || path == "/register" || strings.HasPrefix(path, "/verify-email") || strings.HasPrefix(path, "/confirm-email-change")

		if !isPublic {
			// Auth check for AuthMiddleware
			mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified FROM users WHERE id = $1")).WithArgs(pgxmock.AnyArg()).
				WillReturnRows(pgxmock.NewRows([]string{"is_email_verified"}).AddRow(true))
		}

		if extraMocks != nil {
			extraMocks()
		}

		// Optional: LogActivity if it's a logout or other specific calls
		if path == "/logout" {
		}

		t.Logf("Starting request %s %s", method, path)
		var req *http.Request
		var err error
		if body != nil {
			req, err = http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, err = http.NewRequest(method, ts.URL+path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
		}
		if sessionCookie != nil {
			req.AddCookie(sessionCookie)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if len(expectedCodes) > 0 {
			found := false
			for _, code := range expectedCodes {
				if res.StatusCode == code {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Request %s %s returned status %d, expected one of %v", method, path, res.StatusCode, expectedCodes)
			}
		} else if res.StatusCode >= 400 {
			body, _ := io.ReadAll(res.Body); t.Errorf("Request %s %s returned error status: %d, body: %s", method, path, res.StatusCode, string(body))
		}
		t.Logf("Response %s %s: %d", method, path, res.StatusCode)
		if res.StatusCode == http.StatusFound {
			t.Logf("Redirect location: %s", res.Header.Get("Location"))
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	doAuthReqForm := func(method, path string, form url.Values, extraMocks func(), expectedCodes ...int) *http.Response {
		isPublic := path == "/login" || path == "/register"

		if !isPublic {
			// Auth check for AuthMiddleware
			mock.ExpectQuery(regexp.QuoteMeta("SELECT is_email_verified FROM users WHERE id = $1")).WithArgs(pgxmock.AnyArg()).
				WillReturnRows(pgxmock.NewRows([]string{"is_email_verified"}).AddRow(true))
		}

		if extraMocks != nil {
			extraMocks()
		}

		t.Logf("Starting form request %s %s", method, path)
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("Failed to create form request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if sessionCookie != nil {
			req.AddCookie(sessionCookie)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("Form request failed: %v", err)
		}

		if len(expectedCodes) > 0 {
			found := false
			for _, code := range expectedCodes {
				if res.StatusCode == code {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Form request %s %s returned status %d, expected one of %v", method, path, res.StatusCode, expectedCodes)
			}
		} else if res.StatusCode >= 400 {
			body, _ := io.ReadAll(res.Body); t.Errorf("Form request %s %s returned error status: %d, body: %s", method, path, res.StatusCode, string(body))
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	// 1. Dashboard
	doAuthReq("GET", "/dashboard", nil, func() {
		// Metrics (5 args: userID, searchQuery, startDate, endDate, statusFilter)
		mock.ExpectQuery("SELECT.*COUNT.*total_cves").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit", "prog"}).AddRow(3, 0, 0, 0))
		
		// List (at least 7 args: userID, searchQuery, startDate, endDate, pageSize, offset, statusFilter?)
		// The statusFilter is sometimes at $10. We'll just use AnyArgs by using a large number or fixing it.
		// Actually, let's use a regex that matches ANY number of args if possible? No.
		// We'll just provide 10 AnyArgs.
		mock.ExpectQuery("SELECT DISTINCT.*FROM cves").WithArgs(
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), 
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "desc", "score", "vector", "kev", "pub", "upd", "status", "refs", "notes"}).
				AddRow(1, "CVE-2024-0001", "Test 1", 7.5, "V1", false, time.Now(), time.Now(), "active", []string{}, ""))
		
		// Distribution (same 5 args as metrics)
		mock.ExpectQuery("SELECT c.cvss_score FROM cves").WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"score_distribution"}).AddRow("{}"))
	})

	// 2. Subscriptions GET & POST
	doAuthReq("GET", "/subscriptions", nil, func() {
		mock.ExpectQuery("SELECT id, keyword, min_severity, webhook_url, enable_email, enable_webhook FROM user_subscriptions").WithArgs(pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook"}).AddRow(1, "test", 5.5, "", false, false))
	})
	subForm := url.Values{}
	subForm.Add("keyword", "test")
	subForm.Add("min_severity", "5.5")
	doAuthReqForm("POST", "/subscriptions", subForm, func() {
		mock.ExpectExec("INSERT INTO user_subscriptions").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	})

	// 3. Export
	doAuthReq("GET", "/export", nil, func() {
		mock.ExpectQuery("SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"c.cve_id", "c.description", "c.cvss_score", "c.cisa_kev", "c.published_date"}).AddRow("CVE-2024-0001", "Test", 7.5, false, time.Now()))
	})

	// 4. API Status
	statusBody, _ := json.Marshal(map[string]interface{}{"cve_id": 1, "status": "resolved"})
	doAuthReq("POST", "/api/status", statusBody, func() {
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	})

	// 5. Settings
	doAuthReq("GET", "/settings", nil, func() { mock.ExpectQuery("SELECT email, is_totp_enabled FROM users").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).AddRow("test@test.com", false)) })

	// 6. Change Password
	pwForm := url.Values{}
	pwForm.Add("current_password", "password123")
	pwForm.Add("new_password", "password456")
	pwForm.Add("confirm_password", "password456")
	doAuthReqForm("POST", "/settings/password", pwForm, func() {
		mock.ExpectQuery("SELECT email, is_totp_enabled, password_hash").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled", "password_hash", "totp_secret"}).AddRow("test@test.com", false, string(hashedPassword), ""))
		mock.ExpectQuery("SELECT password_hash, is_totp_enabled").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hashedPassword), false, ""))
		mock.ExpectExec("UPDATE users SET password_hash").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	})

	// 7. Activity Log
	doAuthReq("GET", "/activity", nil, func() { mock.ExpectQuery("SELECT id, activity_type").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).AddRow(1, "login", "desc", "127.0.0.1", time.Now())) })
	doAuthReq("GET", "/activity/export", nil, func() { mock.ExpectQuery("SELECT id, activity_type").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).AddRow(1, "login", "desc", "127.0.0.1", time.Now())) })

	// 8. Alert History
	doAuthReq("GET", "/alerts", nil, func() { mock.ExpectQuery("SELECT ah.sent_at").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"sent_at", "cve_id", "description", "cvss_score"}).AddRow(time.Now(), "CVE-1", "desc", 5.0)) })

	// 9. Bulk Update
	bulkBody, _ := json.Marshal(map[string]interface{}{
		"cve_ids": []int{1, 2, 3},
		"status":  "resolved",
	})
	doAuthReq("POST", "/api/status/bulk", bulkBody, func() {
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()
	})

	// 9. Change Email (Initial request)
	emailForm := url.Values{}
	emailForm.Add("new_email", "new_web_test@example.com")
	emailForm.Add("password", "password123")
	doAuthReqForm("POST", "/settings/email", emailForm, func() {
		mock.ExpectQuery("SELECT email, is_totp_enabled").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).AddRow("test@test.com", false))
		mock.ExpectQuery("SELECT id, email, password_hash").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).AddRow(1, "test@test.com", string(hashedPassword), true, false, "", false))
		mock.ExpectExec("INSERT INTO email_change_requests").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	})

	// Confirm email change (simulating both links clicked)
	var oldToken, newToken string
	mock.ExpectQuery("SELECT old_email_token, new_email_token FROM email_change_requests").WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"old_email_token", "new_email_token"}).AddRow("old", "new"))
	if err := db.Pool.QueryRow(ctx, "SELECT old_email_token, new_email_token FROM email_change_requests WHERE user_id = $1", userID).Scan(&oldToken, &newToken); err != nil {
		t.Fatalf("Failed to scan email change tokens: %v", err)
	}

	// Confirm old
	doAuthReq("GET", "/confirm-email-change?token="+oldToken, nil, func() {
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email, old_email_confirmed").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).AddRow(1, "new_web_test@example.com", false, false, oldToken, newToken))
		mock.ExpectExec("UPDATE email_change_requests SET old_email_confirmed").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()
	})
	// Confirm new
	doAuthReq("GET", "/confirm-email-change?token="+newToken, nil, func() {
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email, old_email_confirmed").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).AddRow(1, "new_web_test@example.com", true, false, oldToken, newToken))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM email_change_requests").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectCommit()
	})

	// 10. TOTP Handlers
	doAuthReq("POST", "/settings/totp/generate", nil, func() {
		mock.ExpectQuery("SELECT email FROM users").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("test@test.com"))
		mock.ExpectExec("UPDATE users SET totp_secret").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	})
	totpForm := url.Values{}
	totpForm.Add("totp_code", "123456")
	doAuthReqForm("POST", "/settings/totp/verify", totpForm, func() {


	})

	// 11. Delete Subscription
	delForm := url.Values{}
	delForm.Add("id", "1")
	doAuthReqForm("POST", "/subscriptions/delete", delForm, func() {
		mock.ExpectExec("DELETE FROM user_subscriptions").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 1))
	})

	// 12. RSS Feed (use updated email after email change)
	var token string
	mock.ExpectQuery("SELECT rss_feed_token FROM users").WithArgs("new_web_test@example.com").
		WillReturnRows(pgxmock.NewRows([]string{"rss_feed_token"}).AddRow("rss_token"))
	if err := db.Pool.QueryRow(ctx, "SELECT rss_feed_token FROM users WHERE email = $1", "new_web_test@example.com").Scan(&token); err != nil {
		t.Fatalf("Failed to scan RSS token: %v", err)
	}
	doAuthReq("GET", "/feed?token="+token, nil, func() {
		mock.ExpectQuery("SELECT id FROM users").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery("SELECT DISTINCT").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"c.cve_id", "c.description", "c.cvss_score", "c.published_date"}).AddRow("CVE-2024-0001", "Test", 7.5, time.Now()))
	})

	// 13. Public Routes Error cases
	// Register with existing email (email was changed to new_web_test@example.com)
	formErr := url.Values{}
	formErr.Add("email", "new_web_test@example.com")
	formErr.Add("password", "password123")
	reqRegErr, _ := http.NewRequest("POST", ts.URL+"/register", strings.NewReader(formErr.Encode()))
	reqRegErr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resRegErr, err := client.Do(reqRegErr)
	if err != nil {
		t.Fatalf("Failed to request register error: %v", err)
	}
	_ = resRegErr.Body.Close()

	// Verify with invalid token (expect 400 or 200 with error message)
	doAuthReq("GET", "/verify-email?token=invalid", nil, nil, http.StatusBadRequest, http.StatusOK)

	// 13. Logout
	doAuthReq("POST", "/logout", nil, nil)

	// 14. Delete Account
	// Login again with updated credentials (email changed to new_web_test@example.com, password changed to password456)
	reLoginForm := url.Values{}
	reLoginForm.Add("email", "new_web_test@example.com")
	reLoginForm.Add("password", "password456")
	reqLogNew, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(reLoginForm.Encode()))
	reqLogNew.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resLogDel, err := client.Do(reqLogNew)
	if err != nil {
		t.Fatalf("Failed to login post-email change: %v", err)
	}
	defer func() { _ = resLogDel.Body.Close() }()
	for _, cookie := range resLogDel.Cookies() {
		if cookie.Name == "session-name" {
			sessionCookie = cookie
			break
		}
	}
	delAccForm := url.Values{}
	delAccForm.Add("password", "password123")
	doAuthReqForm("POST", "/settings/delete", delAccForm, func() {
		mock.ExpectQuery("SELECT email, is_totp_enabled, password_hash").WithArgs(pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled", "password_hash", "totp_secret"}).AddRow("test@test.com", false, string(hashedPassword), ""))
		mock.ExpectExec("DELETE FROM users").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("DELETE", 1))
	})
}

func TestInitTemplates(t *testing.T) {
    if err := os.Chdir("../.."); err != nil {
		t.Logf("Warning: Failed to chdir: %v", err)
	}
	defer func() { _ = os.Chdir("internal/web") }()
    InitTemplates()
}
