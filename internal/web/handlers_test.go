package web

import (
	"cve-tracker/internal/db"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// Setup for all tests in this package
	origWD, _ := os.Getwd()
	_ = os.Chdir("../..")
	InitTemplatesWithFuncs()
	InitSession()
	_, _ = db.SetupTestRedis()
	_ = os.Chdir(origWD)
	os.Exit(m.Run())
}

func TestIndexHandler(t *testing.T) {
	t.Run("Unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		IndexHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr.Code)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Errorf("expected redirect to /login, got %s", rr.Header().Get("Location"))
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}
		
		rr2 := httptest.NewRecorder()
		IndexHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr2.Code)
		}
		if rr2.Header().Get("Location") != "/dashboard" {
			t.Errorf("expected redirect to /dashboard, got %s", rr2.Header().Get("Location"))
		}
	})
}

func TestLoginHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("GET", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/login", nil)
		rr := httptest.NewRecorder()
		LoginHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("POST_InvalidCredentials", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, email").WithArgs("wrong@test.com").
			WillReturnError(sql.ErrNoRows)
		
		form := "email=wrong@test.com&password=wrong"
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		LoginHandler(rr, req)
		
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK (with error message), got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Invalid credentials") {
			t.Error("expected body to contain 'Invalid credentials'")
		}
	})

	t.Run("POST_Success", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT id, email").WithArgs("test@test.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "test@test.com", string(hashedPassword), true, false, "", false))
		
		form := "email=test@test.com&password=password123"
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:1234"

		// Activity Log expect
		mock.ExpectExec("INSERT INTO user_activity_logs").
			WithArgs(1, "login", "Successful login", "1.2.3.4", req.UserAgent()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		rr := httptest.NewRecorder()
		LoginHandler(rr, req)
		
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 found, got %d", rr.Code)
		}
	})
}

func TestDashboardHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/dashboard", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		// Metrics Query
		// args: [userID, searchQuery, startDate, endDate, padding]
		mock.ExpectQuery("SELECT").WithArgs(1, "", "", "", "").
			WillReturnRows(pgxmock.NewRows([]string{"total_cves", "kev_count", "critical_count", "in_progress_count"}).
				AddRow(100, 5, 10, 2))

		// CVEs Query
		// args: [userID, searchQuery, startDate, endDate, padding, pageSize, offset]
		now := time.Now()
		mock.ExpectQuery("SELECT").WithArgs(1, "", "", "", "", 20, 0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes"}).
				AddRow(1, "CVE-2024-0001", "Test CVE", 7.5, "CVSS:3.1/...", false, now, now, "active", []string{"http://example.com"}, "some notes"))

		// Severity Dist Query
		mock.ExpectQuery("SELECT c.cvss_score").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"cvss_score"}).AddRow(7.5).AddRow(9.0))

		rr2 := httptest.NewRecorder()
		DashboardHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if !strings.Contains(rr2.Body.String(), "CVE-2024-0001") {
			t.Error("expected body to contain 'CVE-2024-0001'")
		}
	})
}

func TestUpdateCVEStatusHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO user_cve_status").
			WithArgs(1, 101, "resolved").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req := httptest.NewRequest("POST", "/api/status", strings.NewReader(`{"cve_id": 101, "status": "resolved"}`))
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("POST", "/api/status", strings.NewReader(`{"cve_id": 101, "status": "resolved"}`))
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		UpdateCVEStatusHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestBulkUpdateCVEStatusHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(1, 101, "resolved").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(1, 102, "resolved").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		req := httptest.NewRequest("POST", "/api/status/bulk", strings.NewReader(`{"cve_ids": [101, 102], "status": "resolved"}`))
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("POST", "/api/status/bulk", strings.NewReader(`{"cve_ids": [101, 102], "status": "resolved"}`))
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		BulkUpdateCVEStatusHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestActivityLogHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/activity", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/activity", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT id, activity_type").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow(1, "login", "Successful login", "1.1.1.1", time.Now()))

		rr2 := httptest.NewRecorder()
		ActivityLogHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestExportActivityLogHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/activity/export", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/activity/export", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT id, activity_type").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow(1, "login", "Successful login", "1.1.1.1", time.Now()))

		rr2 := httptest.NewRecorder()
		ExportActivityLogHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if rr2.Header().Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", rr2.Header().Get("Content-Type"))
		}
	})
}

func TestRegisterHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	redisMock, _ := db.SetupTestRedis()
	defer redisMock.Close()

	t.Run("GET", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/register", nil)
		rr := httptest.NewRecorder()
		RegisterHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("POST_Success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO users").
			WithArgs("new@test.com", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		form := "email=new@test.com&password=password123"
		req := httptest.NewRequest("POST", "/register", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		RegisterHandler(rr, req)
		
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "Registration successful") {
			t.Errorf("expected body to contain 'Registration successful', got: %s", rr.Body.String())
		}
	})
}

func TestVerifyEmailHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec("UPDATE users").WithArgs("tok").WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		req := httptest.NewRequest("GET", "/verify-email?token=tok", nil)
		rr := httptest.NewRecorder()
		VerifyEmailHandler(rr, req)
		
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})
}

func TestLogoutHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/logout", nil)
		rr := httptest.NewRecorder()
		LogoutHandler(rr, req)
		
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 found, got %d", rr.Code)
		}
	})
}

func TestAlertHistoryHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/alerts", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/alerts", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT ah.sent_at").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"sent_at", "cve_id", "description", "cvss_score"}).
				AddRow(time.Now(), "CVE-2024-0001", "Test", 7.5))

		rr2 := httptest.NewRecorder()
		AlertHistoryHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestSettingsHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/settings", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("GET", "/settings", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT email, is_totp_enabled").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"email", "is_totp_enabled"}).AddRow("test@test.com", false))

		rr2 := httptest.NewRecorder()
		SettingsHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestGenerateTOTPHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings/totp/generate", nil)
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("POST", "/settings/totp/generate", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT email").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"email"}).AddRow("test@test.com"))
		mock.ExpectExec("UPDATE users SET totp_secret").WithArgs(pgxmock.AnyArg(), 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		rr2 := httptest.NewRecorder()
		GenerateTOTPHandler(rr2, req)
		
		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
		if rr2.Header().Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", rr2.Header().Get("Content-Type"))
		}
	})
}

func TestVerifyTOTPHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("InvalidCode", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(`{"code": "123456"}`))
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader(`{"code": "123456"}`))
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT totp_secret").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("JBSWY3DPEHPK3PXP"))

		rr2 := httptest.NewRecorder()
		VerifyTOTPHandler(rr2, req)
		
		if rr2.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", rr2.Code)
		}
	})
}

func TestChangePasswordHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("current"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hashedPassword), false, ""))
		mock.ExpectExec("UPDATE users SET password_hash").WithArgs(pgxmock.AnyArg(), 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		form := "current_password=current&new_password=new123&confirm_password=new123"
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session, _ := store.Get(req, "session-name")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		session.Save(req, rr)
		
		req = httptest.NewRequest("POST", "/settings/password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		ChangePasswordHandler(rr2, req)
		
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 found, got %d", rr2.Code)
		}
	})
}
