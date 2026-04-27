package worker

import (
	"context"
	"cve-tracker/internal/db"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestSyncErrorConditions(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	ctx := context.Background()
	t.Setenv("NVD_API_KEY", "test")

	t.Run("CISAKEV_Non200", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		oldURL := defaultCISAKEVURL
		defaultCISAKEVURL = ts.URL
		defer func() { defaultCISAKEVURL = oldURL }()
		fetchFromCISAKEV(ctx)
	})

	t.Run("CISAKEV_InvalidJSON", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{invalid json}")
		}))
		defer ts.Close()
		oldURL := defaultCISAKEVURL
		defaultCISAKEVURL = ts.URL
		defer func() { defaultCISAKEVURL = oldURL }()
		fetchFromCISAKEV(ctx)
	})

	t.Run("EPSS_Non200", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()
		oldURL := defaultEPSSBaseURL
		defaultEPSSBaseURL = ts.URL
		defer func() { defaultEPSSBaseURL = oldURL }()
		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-1"))
		syncEPSS(ctx)
	})

	t.Run("NVD_ErrorCodes", func(t *testing.T) {
		codes := []int{http.StatusInternalServerError, http.StatusBadRequest}
		for _, code := range codes {
			t.Run(fmt.Sprintf("Status_%d", code), func(t *testing.T) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(code)
				}))
				defer ts.Close()
				oldURL := defaultNVDBaseURL
				defaultNVDBaseURL = ts.URL
				defer func() { defaultNVDBaseURL = oldURL }()
				mock.ExpectQuery("SELECT value FROM sync_state").WillReturnError(fmt.Errorf("no sync"))
				shortCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
				defer cancel()
				runFullSync(shortCtx, true)
			})
		}
	})
}

func TestHelpersCoverage(t *testing.T) {
	t.Run("SanitizeHeader", func(t *testing.T) {
		input := "Line 1\r\nLine 2\nLine 3"
		expected := "Line 1Line 2Line 3"
		if got := sanitizeHeader(input); got != expected {
			t.Errorf("sanitizeHeader failed: got %q, want %q", got, expected)
		}
	})

	t.Run("ClassifyVendorAdvisories", func(t *testing.T) {
		refs := []string{
			"https://example.com/advisory/123",
			"https://github.com/advisories/GHSA-123",
			"https://example.com/other",
		}
		advisories := classifyVendorAdvisories(refs)
		if len(advisories) != 2 {
			t.Errorf("expected 2 advisories, got %d", len(advisories))
		}
	})

	t.Run("SendMailWithTimeout_Errors", func(t *testing.T) {
		err := sendMailWithTimeout("localhost", "25", "user", "pass", "bad-email", []string{"to@example.com"}, []byte("msg"))
		if err == nil {
			t.Error("expected error for invalid from address")
		}
		err = sendMailWithTimeout("localhost", "25", "user", "pass", "from@example.com", []string{}, []byte("msg"))
		if err == nil {
			t.Error("expected error for no recipients")
		}
	})
}

func TestStartWorkerCleanExit(t *testing.T) {
	mock, _ := db.SetupTestDB()
	defer mock.Close()
	mr, _ := db.SetupTestRedis()
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	StartWorker(ctx)
}

func TestFetchCVEsPeriodically_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetchCVEsPeriodically(ctx)
}

func TestEmailSender_Coverage(t *testing.T) {
	t.Run("MissingConfig", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "")
		sender := &realEmailSender{}
		err := sender.SendEmail("to@example.com", "sub", "body")
		if err == nil {
			t.Error("expected error")
		}
	})
	t.Run("InvalidRecipient", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "localhost")
		t.Setenv("SMTP_FROM", "from@example.com")
		sender := &realEmailSender{}
		err := sender.SendEmail("invalid\n", "sub", "body")
		if err == nil {
			t.Error("expected error")
		}
	})
}
