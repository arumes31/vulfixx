package web

import (

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
		mock, _ := db.SetupTestDB()
		defer mock.Close()

		// Expectations for PublicDashboardHandler
		mock.ExpectQuery("SELECT").WithArgs("", "", "", 0.0, 10.0).WillReturnRows(pgxmock.NewRows([]string{"total", "kev", "crit"}).AddRow(100, 10, 5))
		mock.ExpectQuery("SELECT").WithArgs("", "", "", 0.0, 10.0, 20, 0).WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "cvss_vector", "cisa_kev", "published_date", "updated_date", "status", "references", "notes"}).
			AddRow(1, "CVE-2024-0001", "Test", 7.5, "", false, time.Now(), time.Now(), "active", []string{}, ""))
		mock.ExpectQuery("SELECT cvss_score").WithArgs().WillReturnRows(pgxmock.NewRows([]string{"cvss_score"}).AddRow(7.5))

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		IndexHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("Authenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		IndexHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr2.Code)
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
		// auth.Login query: SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, ''), is_admin FROM users WHERE email = $1
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE").WithArgs("test@example.com").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		LoginHandler(rr, req)
		// LoginHandler renders template with 200 OK on failure
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("POST_Success", func(t *testing.T) {
		hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE").WithArgs("test@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "test@example.com", string(hash), true, false, "", false))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "login", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		req := httptest.NewRequest("POST", "/login", strings.NewReader("email=test@example.com&password=password"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		LoginHandler(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr.Code)
		}
	})
}

func TestDashboardHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/dashboard", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		// Metrics Query (10 args)
		// userID, searchQuery, startDate, endDate, pageSize, offset, statusFilter, activeTeamID, minCvss, maxCvss
		mock.ExpectQuery("SELECT").WithArgs(1, "", "", "", 20, 0, "", 0, 0.0, 10.0).
			WillReturnRows(pgxmock.NewRows([]string{"total_cves", "kev_count", "critical_count", "in_progress_count"}).
				AddRow(100, 5, 10, 2))

		// CVEs Query (10 args)
		now := time.Now()
		mock.ExpectQuery("SELECT").WithArgs(1, "", "", "", 20, 0, "", 0, 0.0, 10.0).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "vector_string", "cisa_kev", "published_date", "updated_date", "status", "references", "notes"}).
				AddRow(1, "CVE-2024-0001", "Test CVE", 7.5, "CVSS:3.1/...", false, now, now, "active", []string{"http://example.com"}, "some notes"))

		// Severity Dist Query (10 args)
		mock.ExpectQuery("SELECT c.cvss_score").WithArgs(1, "", "", "", 20, 0, "", 0, 0.0, 10.0).
			WillReturnRows(pgxmock.NewRows([]string{"cvss_score"}).AddRow(7.5).AddRow(9.0))

		rr2 := httptest.NewRecorder()
		DashboardHandler(rr2, req)

		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestUpdateCVEStatusHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO user_cve_status").
			WithArgs(1, pgxmock.AnyArg(), "resolved", []int{101}).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "cve_status_bulk_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		req := httptest.NewRequest("POST", "/api/status", strings.NewReader(`{"cve_ids": [101], "status": "resolved"}`))
		req.Header.Set("Accept", "application/json")
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/status", strings.NewReader(`{"cve_ids": [101], "status": "resolved"}`))
		req.Header.Set("Accept", "application/json")
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

func TestBulkUpdateCVEStatusHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO user_cve_status").WithArgs(1, pgxmock.AnyArg(), "resolved", []int{101, 102}).WillReturnResult(pgxmock.NewResult("INSERT", 2))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "cve_status_bulk_updated", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		req := httptest.NewRequest("POST", "/api/status/bulk", strings.NewReader(`{"cve_ids": [101, 102], "status": "resolved"}`))
		req.Header.Set("Accept", "application/json")
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/api/status/bulk", strings.NewReader(`{"cve_ids": [101, 102], "status": "resolved"}`))
		req.Header.Set("Accept", "application/json")
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
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/activity", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"id", "activity_type", "description", "ip_address", "created_at"}).
				AddRow(1, "login", "User logged in", "127.0.0.1", time.Now()))

		rr2 := httptest.NewRecorder()
		ActivityLogHandler(rr2, req)

		if rr2.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr2.Code)
		}
	})
}

func TestAlertHistoryHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/alerts", nil)
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("GET", "/alerts", nil)
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"sent_at", "cve_id", "description", "cvss_score"}).
				AddRow(time.Now(), "CVE-2023-0001", "Alert desc", 7.5))

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
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

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

func TestChangePasswordHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		hash, _ := bcrypt.GenerateFromPassword([]byte("current"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash"}).AddRow(string(hash)))
		mock.ExpectExec("UPDATE users").WithArgs(pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("INSERT INTO user_activity_logs").WithArgs(1, "password_changed", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		form := "current_password=current&new_password=new123&confirm_password=new123"
		req := httptest.NewRequest("POST", "/settings/password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/settings/password", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		rr2 := httptest.NewRecorder()
		ChangePasswordHandler(rr2, req)
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302 redirect, got %d", rr2.Code)
		}
	})
}

func TestVerifyTOTPHandler(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()

	t.Run("InvalidCode", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader("totp_code=123456"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session, _ := store.Get(req, "vulfixx-session")
		session.Values["user_id"] = 1
		session.Values["totp_setup_ts"] = time.Now().Unix()
		rr := httptest.NewRecorder()
		_ = session.Save(req, rr)

		req = httptest.NewRequest("POST", "/settings/totp/verify", strings.NewReader("totp_code=123456"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rr.Result().Cookies() {
			req.AddCookie(c)
		}

		mock.ExpectQuery("SELECT totp_secret FROM users WHERE id = $1").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"totp_secret"}).AddRow("secret"))

		rr2 := httptest.NewRecorder()
		VerifyTOTPHandler(rr2, req)
		// On failure it redirects back to /settings?error=...
		if rr2.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", rr2.Code)
		}
	})
}
