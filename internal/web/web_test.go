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
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "cveuser")
	os.Setenv("DB_PASSWORD", "cvepass")
	os.Setenv("DB_NAME", "cvetracker")
	os.Setenv("REDIS_URL", "localhost:6379")
	os.Setenv("SESSION_KEY", "supersecretkey")
	os.Setenv("CSRF_KEY", "0123456789abcdef0123456789abcdef")

	if err := db.InitDB(); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	if err := db.InitRedis(); err != nil {
		t.Fatalf("Failed to init Redis: %v", err)
	}
	defer db.CloseDB()
	defer db.CloseRedis()

	InitSession()

	// Need to be at project root or templates/ won't load
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}
	InitTemplatesWithFuncs()

	// Setup a router
	r := mux.NewRouter()
	r.Use(ProxyMiddleware)
	r.HandleFunc("/", IndexHandler).Methods("GET")
	r.Handle("/login", RateLimitMiddleware(http.HandlerFunc(LoginHandler))).Methods("GET", "POST")
	r.Handle("/register", RateLimitMiddleware(http.HandlerFunc(RegisterHandler))).Methods("GET", "POST")
	r.HandleFunc("/verify-email", VerifyEmailHandler).Methods("GET")
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
	protected.HandleFunc("/settings/delete", DeleteAccountHandler).Methods("POST")

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Seed user
	ctx := context.Background()
	_, _ = db.Pool.Exec(ctx, "DELETE FROM users WHERE email = 'web_test@example.com'")
	_, _ = db.Pool.Exec(ctx, "INSERT INTO users (email, password_hash, is_email_verified) VALUES ('web_test@example.com', '$2a$10$xyz', TRUE)")
	var userID int
	_ = db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = 'web_test@example.com'").Scan(&userID)

	// Mock a session cookie to bypass login for protected routes
	// Actually, gorilla sessions need a real cookie. Let's just login to get it if we can't forge easily.
	// But we don't know the hash of password since we inserted dummy hash.
	// Let's create a real user using Register
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
	_, _ = client.Do(reqReg)

	// Verify email manually
	_, _ = db.Pool.Exec(ctx, "UPDATE users SET is_email_verified = TRUE WHERE email = 'web_test2@example.com'")

	// Login to get session cookie
	loginForm := url.Values{}
	loginForm.Add("email", "web_test2@example.com")
	loginForm.Add("password", "password123")
	reqLog, _ := http.NewRequest("POST", ts.URL+"/login", strings.NewReader(loginForm.Encode()))
	reqLog.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resLog, _ := client.Do(reqLog)

	var sessionCookie *http.Cookie
	for _, cookie := range resLog.Cookies() {
		if cookie.Name == "session-name" {
			sessionCookie = cookie
			break
		}
	}

	doAuthReq := func(method, path string, body []byte) *http.Response {
		var req *http.Request
		if body != nil {
			req, _ = http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, _ = http.NewRequest(method, ts.URL+path, nil)
		}
		if sessionCookie != nil {
			req.AddCookie(sessionCookie)
		}
		res, _ := client.Do(req)
		return res
	}

	doAuthReqForm := func(method, path string, form url.Values) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if sessionCookie != nil {
			req.AddCookie(sessionCookie)
		}
		res, _ := client.Do(req)
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

	// 10. Change Email
	emailForm := url.Values{}
	emailForm.Add("new_email", "new_web_test@example.com")
	emailForm.Add("password", "password456")
	doAuthReqForm("POST", "/settings/email", emailForm)

	// 10. TOTP Handlers
	doAuthReq("POST", "/settings/totp/generate", nil)
	totpForm := url.Values{}
	totpForm.Add("totp_code", "123456")
	doAuthReqForm("POST", "/settings/totp/verify", totpForm)

	// 11. Delete Subscription
	delForm := url.Values{}
	delForm.Add("id", "1")
	doAuthReqForm("POST", "/subscriptions/delete", delForm)

	// 12. RSS Feed
	var token string
	_ = db.Pool.QueryRow(ctx, "SELECT email_verify_token FROM users WHERE email = 'web_test2@example.com'").Scan(&token)
	doAuthReq("GET", "/feed?token="+token, nil)

	// 13. Public Routes Error cases
	// Register with existing email
	formErr := url.Values{}
	formErr.Add("email", "web_test2@example.com")
	formErr.Add("password", "password123")
	reqRegErr, _ := http.NewRequest("POST", ts.URL+"/register", strings.NewReader(formErr.Encode()))
	reqRegErr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, _ = client.Do(reqRegErr)

	// Verify with invalid token
	doAuthReq("GET", "/verify-email?token=invalid", nil)

	// 13. Logout
	doAuthReq("POST", "/logout", nil)

	// 14. Delete Account
	// Login again to delete
	resLogDel, _ := client.Do(reqLog)
	for _, cookie := range resLogDel.Cookies() {
		if cookie.Name == "session-name" {
			sessionCookie = cookie
			break
		}
	}
	delAccForm := url.Values{}
	delAccForm.Add("password", "password123")
	doAuthReqForm("POST", "/settings/delete", delAccForm)
}
