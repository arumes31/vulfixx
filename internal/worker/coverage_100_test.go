package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

// MockHTTPClient is a flexible HTTP client mock
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("DoFunc not set")
}

// MockEmailSender is a flexible EmailSender mock
type MockEmailSender struct {
	SendEmailFunc func(to, subject, body string) error
}

func (m *MockEmailSender) SendEmail(to, subject, body string) error {
	if m.SendEmailFunc != nil {
		return m.SendEmailFunc(to, subject, body)
	}
	return nil
}

func TestCoverage100_FetchFromNVD(t *testing.T) {
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

	t.Run("Status_403_RateLimit", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader("Forbidden")),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		
		// Use a short timeout context to break the loop/sleep
		shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		
		w.runFullSync(shortCtx, false)
	})

	t.Run("Malformed_JSON", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("{malformed")),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		
		w.runFullSync(ctx, false)
	})

	t.Run("Empty_Vulnerabilities", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				resp := NVDResponse{
					TotalResults:    0,
					Vulnerabilities: []NVDCVEEntry{},
				}
				data, _ := json.Marshal(resp)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(string(data))),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		mock.ExpectExec("INSERT INTO worker_sync_stats").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		
		w.runFullSync(ctx, false)
	})
}

func TestCoverage100_SyncEPSS(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	_, _ = db.SetupTestRedis()

	t.Run("Success", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				data := `{"data":[{"epss":"0.0123"}]}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(data)),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-EPSS-1"))
		mock.ExpectExec("UPDATE cves SET epss_score = \\$1 WHERE cve_id = \\$2").WithArgs(0.0123, "CVE-EPSS-1").WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		// Use short ctx to skip the time.After(100ms) delay if needed, or just let it run
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		w.syncEPSS(ctx)
	})

	t.Run("DBError", func(t *testing.T) {
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, http.DefaultClient)
		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnError(fmt.Errorf("db error"))
		w.syncEPSS(context.Background())
	})

	t.Run("RateLimited", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-EPSS-RATE"))
		
		// Short timeout to not wait 5 seconds
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		w.syncEPSS(ctx)
	})
}

func TestCoverage100_SyncGitHub(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	_, _ = db.SetupTestRedis()

	t.Run("Success", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				data := `{"total_count":42}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(data)),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-GH-1"))
		mock.ExpectExec("UPDATE cves SET github_poc_count = \\$1 WHERE cve_id = \\$2").WithArgs(42, "CVE-GH-1").WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		w.syncGitHubBuzz(ctx)
	})

	t.Run("Forbidden", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-GH-FORBIDDEN"))
		w.syncGitHubBuzz(context.Background())
	})
}

func TestCoverage100_EvaluateSubscriptions(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	_, _ = db.SetupTestRedis()

	t.Run("FilterLogic_Complex", func(t *testing.T) {
		cve := &models.CVE{
			ID:          1,
			CVEID:       "CVE-COMPLEX",
			Description: "Serious exploit in software",
			CVSSScore:   9.8,
			EPSSScore:   0.5,
			CISAKEV:     true,
			GitHubPoCCount: 10,
		}

		// Test evaluateComplexFilter directly for better coverage
		testCases := []struct {
			logic string
			want  bool
		}{
			{"epss > 0.1", true},
			{"epss > 0.6", false},
			{"cisa = true", true},
			{"buzz >= 5", true},
			{"regex: exploit", true},
			{"regex: unknown", false},
			{"unknown-field", true},
		}

		for _, tc := range testCases {
			if got := evaluateComplexFilter(tc.logic, cve); got != tc.want {
				t.Errorf("evaluateComplexFilter(%q) = %v, want %v", tc.logic, got, tc.want)
			}
		}
	})

	t.Run("AssetMatch_Regex", func(t *testing.T) {
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, http.DefaultClient)
		ctx := context.Background()
		cve := &models.CVE{
			ID:          1,
			CVEID:       "CVE-ASSET",
			Description: "Vulnerability in WordPress Plugin",
			CVSSScore:   8.0,
		}

		mock.ExpectQuery("SELECT s.id, s.user_id").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "filter_logic", "email"}))
		mock.ExpectQuery("SELECT ak.keyword, a.user_id").WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email", "name"}).
			AddRow("wordpress", 1, "user@example.com", "My Site"))
		
		// notifyIfNew
		mock.ExpectExec("INSERT INTO alert_history").WillReturnResult(pgxmock.NewResult("INSERT", 1))
		// fetchOSINTLinks (mocked in another way or just let it fail)
		mock.ExpectQuery("SELECT url FROM cve_osint_links").WillReturnRows(pgxmock.NewRows([]string{"url"}))

		w.evaluateSubscriptions(ctx, cve)
	})
}

func TestCoverage100_SendAlert(t *testing.T) {
	mock, _ := db.SetupTestDB()
	_, _ = db.SetupTestRedis()

	t.Run("Webhook_Success", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("OK")),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, httpClient)
		
		sub := models.UserSubscription{
			EnableWebhook: true,
			WebhookURL:    "https://example.com/webhook",
		}
		cve := &models.CVE{CVEID: "CVE-WEBHOOK", CVSSScore: 9.0}
		
		w.sendAlert(sub, cve, "user@example.com", "Asset")
	})

	t.Run("Email_FullCoverage", func(t *testing.T) {
		mailer := &MockEmailSender{
			SendEmailFunc: func(to, subject, body string) error {
				return nil
			},
		}
		w := NewWorker(mock, db.RedisClient, mailer, http.DefaultClient)
		
		t.Setenv("BASE_URL", "https://vulfixx.io")
		
		cves := []*models.CVE{
			{CVEID: "CVE-CRIT", CVSSScore: 10.0, CISAKEV: true},
			{CVEID: "CVE-HIGH", CVSSScore: 8.0, References: []string{"https://github.com/advisories/GHSA-1"}},
			{CVEID: "CVE-MED", CVSSScore: 5.0, EPSSScore: 0.1},
			{CVEID: "CVE-LOW", CVSSScore: 2.0},
		}
		
		for _, c := range cves {
			sub := models.UserSubscription{EnableEmail: true}
			// Mock Redis for action token
			db.RedisClient.Set(context.Background(), "alert_action:token", "data", 0)
			
			w.sendAlert(sub, c, "user@example.com", "Asset")
		}
	})
}

func TestCoverage100_WorkerLoops(t *testing.T) {
	mock, _ := db.SetupTestDB()
	_, _ = db.SetupTestRedis()
	w := NewWorker(mock, db.RedisClient, &MockEmailSender{}, http.DefaultClient)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// Test fetchCISAKEVPeriodically
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	
	// Override URL to fail fast
	oldURL := defaultCISAKEVURL
	defaultCISAKEVURL = "http://invalid-url"
	defer func() { defaultCISAKEVURL = oldURL }()
	
	w.fetchCISAKEVPeriodically(ctx)
}
