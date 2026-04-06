package web

import (
	"bytes"
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
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

	if err := db.InitDB(); err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("InitDB failed (skipping): %v", err)
		} else {
			t.Fatalf("InitDB failed: %v", err)
		}
	}
	defer db.CloseDB()

	if err := db.InitRedis(); err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("InitRedis failed (skipping): %v", err)
		} else {
			t.Fatalf("InitRedis failed: %v", err)
		}
	}
	defer db.CloseRedis()

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
	_ = resReg.Body.Close()

	// Verify email manually
	_, _ = db.Pool.Exec(ctx, "UPDATE users SET is_email_verified = TRUE WHERE email = 'web_test2@example.com'")
	var userID int
	if err := db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = 'web_test2@example.com'").Scan(&userID); err != nil {
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
	defer func() { _ = resLog.Body.Close() }()

	var sessionCookie *http.Cookie
	for _, cookie := range resLog.Cookies() {
		if cookie.Name == "session-name" {
			sessionCookie = cookie
			break
		}
	}

	doAuthReq := func(method, path string, body []byte, expectedCodes ...int) *http.Response {
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
			t.Errorf("Request %s %s returned error status: %d", method, path, res.StatusCode)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	doAuthReqForm := func(method, path string, form url.Values, expectedCodes ...int) *http.Response {
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
			t.Errorf("Form request %s %s returned error status: %d", method, path, res.StatusCode)
		}
		t.Cleanup(func() { res.Body.Close() })
		return res
	}

	// 1. Dashboard
	doAuthReq("GET", "/dashboard", nil)

	// 2. Subscriptions GET & POST
	doAuthReq("GET", "/subscriptions", nil)
	subForm := url.Values{}
	subForm.Add("keyword", "test")
	subForm.Add("min_severity", "5.5")
	doAuthReqForm("POST", "/subscriptions", subForm)

	// 3. Export
	doAuthReq("GET", "/export", nil)

	// 4. API Status
	statusBody, _ := json.Marshal(map[string]interface{}{"cve_id": 1, "status": "resolved"})
	doAuthReq("POST", "/api/status", statusBody)

	// 5. Settings
	doAuthReq("GET", "/settings", nil)

	// 6. Change Password
	pwForm := url.Values{}
	pwForm.Add("current_password", "password123")
	pwForm.Add("new_password", "password456")
	pwForm.Add("confirm_password", "password456")
	doAuthReqForm("POST", "/settings/password", pwForm)

	// 7. Activity Log
	doAuthReq("GET", "/activity", nil)
	doAuthReq("GET", "/activity/export", nil)

	// 8. Alert History
	doAuthReq("GET", "/alerts", nil)

	// 9. Bulk Update
	bulkBody, _ := json.Marshal(map[string]interface{}{
		"cve_ids": []int{1, 2, 3},
		"status":  "resolved",
	})
	doAuthReq("POST", "/api/status/bulk", bulkBody)

	// 9. Change Email (Initial request)
	emailForm := url.Values{}
	emailForm.Add("new_email", "new_web_test@example.com")
	emailForm.Add("password", "password456")
	doAuthReqForm("POST", "/settings/email", emailForm)

	// Confirm email change (simulating both links clicked)
	var oldToken, newToken string
	if err := db.Pool.QueryRow(ctx, "SELECT old_email_token, new_email_token FROM email_change_requests WHERE user_id = $1", userID).Scan(&oldToken, &newToken); err != nil {
		t.Fatalf("Failed to scan email change tokens: %v", err)
	}

	// Confirm old
	doAuthReq("GET", "/confirm-email-change?token="+oldToken, nil)
	// Confirm new
	doAuthReq("GET", "/confirm-email-change?token="+newToken, nil)

	// 10. TOTP Handlers
	doAuthReq("POST", "/settings/totp/generate", nil)
	totpForm := url.Values{}
	totpForm.Add("totp_code", "123456")
	doAuthReqForm("POST", "/settings/totp/verify", totpForm)

	// 11. Delete Subscription
	delForm := url.Values{}
	delForm.Add("id", "1")
	doAuthReqForm("POST", "/subscriptions/delete", delForm)

	// 12. RSS Feed (use updated email after email change)
	var token string
	if err := db.Pool.QueryRow(ctx, "SELECT rss_feed_token FROM users WHERE email = 'new_web_test@example.com'").Scan(&token); err != nil {
		t.Fatalf("Failed to scan RSS token: %v", err)
	}
	doAuthReq("GET", "/feed?token="+token, nil)

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
	doAuthReq("GET", "/verify-email?token=invalid", nil, http.StatusBadRequest, http.StatusOK)

	// 13. Logout
	doAuthReq("POST", "/logout", nil)

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
	delAccForm.Add("password", "password456")
	doAuthReqForm("POST", "/settings/delete", delAccForm)
}