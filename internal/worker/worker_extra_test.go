package worker

import (
	"context"
	"cve-tracker/internal/config"
	"cve-tracker/internal/models"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestWorker_EnrichmentRows_Comprehensive(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer mock.Close()

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

	t.Run("UpdateSuccess", func(t *testing.T) {
		// Apache is a known keyword that GetDetectedProduct might pick up if description contains it
		cves := []models.CVE{
			{ID: 1, CVEID: "CVE-2023-0001", Description: "Apache HTTP Server vulnerability", Configurations: models.CVEConfigurations{}, References: []string{}},
		}

		mock.ExpectExec("UPDATE cves SET vendor").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("intelligence_enrichment").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.processEnrichmentRows(context.Background(), cves, 1)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("UpdateError", func(t *testing.T) {
		cves := []models.CVE{
			{ID: 123, CVEID: "CVE-2023-1234", Description: "Apache HTTP Server vulnerability", Configurations: models.CVEConfigurations{}, References: []string{}},
		}

		mock.ExpectExec("UPDATE cves SET vendor").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), 123).
			WillReturnError(errors.New("update error"))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("intelligence_enrichment").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.processEnrichmentRows(context.Background(), cves, 1)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("LLMActive_FailureRetryLoop", func(t *testing.T) {
		orig := config.AppConfig
		defer func() {
			config.AppConfig = orig
		}()
		config.AppConfig.GeminiAPIKey = "dummy-key"
		config.AppConfig.LLMTimeout = 1

		cves := []models.CVE{
			{ID: 1, CVEID: "CVE-1", Description: "desc", Configurations: models.CVEConfigurations{}, References: []string{}},
			{ID: 2, CVEID: "CVE-2", Description: "desc", Configurations: models.CVEConfigurations{}, References: []string{}},
			{ID: 3, CVEID: "CVE-3", Description: "desc", Configurations: models.CVEConfigurations{}, References: []string{}},
			{ID: 4, CVEID: "CVE-4", Description: "desc", Configurations: models.CVEConfigurations{}, References: []string{}},
		}

		// We do NOT expect the stats update because it will exit early during backoff
		// mock.ExpectExec("INSERT INTO worker_sync_stats")...

		// Set mock HTTP client to return 500 to trigger consecutive LLM failures
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(""))}, nil
			},
		}
		w2 := NewWorker(mock, nil, &EmailSenderMock{}, httpClient)

		ctx, cancel := context.WithCancel(context.Background())
		// Cancel immediately so the consecutive failure backoff exits
		cancel()

		w2.processEnrichmentRows(ctx, cves, 4)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestWorker_Health_Comprehensive(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	mock.MatchExpectationsInOrder(false)
	defer mock.Close()

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

	t.Run("CheckWorkerHealth_Success", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM notification_delivery_logs").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync", "inthewild_sync", "threat_intel_sync", "advisory_rss_sync", "intelligence_sync", "intelligence_enrichment", "health_check"}
		mock.ExpectQuery("SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY\\(\\$1\\)").
			WithArgs(tasks).
			WillReturnRows(pgxmock.NewRows([]string{"task_name", "last_run"}).
				AddRow("nvd_sync", time.Now()).
				AddRow("cisa_kev_sync", time.Now()).
				AddRow("epss_sync", time.Now()).
				AddRow("github_buzz_sync", time.Now()).
				AddRow("osv_sync", time.Now()).
				AddRow("greynoise_sync", time.Now()))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("health_check").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.checkWorkerHealth(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("CheckWorkerHealth_StaleAndErrors", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM notification_delivery_logs").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(2))

		tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync", "inthewild_sync", "threat_intel_sync", "advisory_rss_sync", "intelligence_sync", "intelligence_enrichment", "health_check"}
		mock.ExpectQuery("SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY\\(\\$1\\)").
			WithArgs(tasks).
			WillReturnRows(pgxmock.NewRows([]string{"task_name", "last_run"}).
				AddRow("nvd_sync", time.Now().Add(-48*time.Hour)).
				AddRow("epss_sync", time.Now()).
				AddRow("github_buzz_sync", time.Now()).
				AddRow("osv_sync", time.Now()).
				AddRow("greynoise_sync", time.Now()))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("health_check").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.checkWorkerHealth(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("TestLLMConnectivity_EdgeCases", func(t *testing.T) {
		orig := config.AppConfig
		defer func() {
			config.AppConfig = orig
		}()

		// 1. Ollama Happy path
		config.AppConfig.LLMProvider = "ollama"
		config.AppConfig.LLMEndpoint = "http://localhost:11434"
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
			},
		}
		w2 := NewWorker(mock, nil, &EmailSenderMock{}, httpClient)

		w2.TestLLMConnectivity(context.Background())

		// 2. Gemini Happy path
		config.AppConfig.LLMProvider = "gemini"
		config.AppConfig.GeminiAPIKey = "test-key"
		w2.TestLLMConnectivity(context.Background())

		// 3. ArliAI Happy path
		config.AppConfig.LLMProvider = "arliai"
		config.AppConfig.ArliAIAPIKey = "test-key"
		w2.TestLLMConnectivity(context.Background())
	})
}

func TestWorker_DetectDuplicates_Comprehensive(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer mock.Close()

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

	t.Run("HasDuplicates", func(t *testing.T) {
		cve := &models.CVE{
			ID:            1,
			CVEID:         "CVE-2023-0001",
			CWEID:         "CWE-79",
			CVSSScore:     7.5,
			PublishedDate: time.Now(),
			OSINTData:     make(models.JSONBMap),
		}

		mock.ExpectQuery("SELECT cve_id FROM cves").
			WithArgs("CWE-79", 1, 7.5, pgxmock.AnyArg()).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2023-0002").AddRow("CVE-2023-0003"))

		w.detectDuplicates(context.Background(), cve)

		dups, ok := cve.OSINTData["similar_threats"].([]string)
		if !ok || len(dups) != 2 || dups[0] != "CVE-2023-0002" {
			t.Errorf("expected similar threats 'CVE-2023-0002', got %v", cve.OSINTData["similar_threats"])
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestWorker_AdvisoryRSS_Extra(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer mock.Close()

	t.Run("syncAdvisoryRSSPeriodically_Cancel", func(t *testing.T) {
		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		w.syncAdvisoryRSSPeriodically(ctx)
	})

	t.Run("integrateAdvisoryCVE_NoRows", func(t *testing.T) {
		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, cve_id").
			WithArgs("CVE-2023-0001").
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		item := GenericFeedItem{Link: "http://example.com/advisory"}
		feed := AdvisoryFeed{Name: "Test Feed"}

		w.integrateAdvisoryCVE(context.Background(), "CVE-2023-0001", item, feed)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("integrateAdvisoryCVE_QueryError", func(t *testing.T) {
		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, cve_id").
			WithArgs("CVE-2023-0001").
			WillReturnError(errors.New("query error"))
		mock.ExpectRollback()

		item := GenericFeedItem{Link: "http://example.com/advisory"}
		feed := AdvisoryFeed{Name: "Test Feed"}

		w.integrateAdvisoryCVE(context.Background(), "CVE-2023-0001", item, feed)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
