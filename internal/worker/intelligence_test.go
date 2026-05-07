package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestWorker_FetchOSINTLinks(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "hn.algolia.com") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"hits":[{"title":"HN Story","objectID":"123"}]}`)),
				}, nil
			}
			if strings.Contains(req.URL.String(), "reddit.com") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data":{"children":[{"data":{"title":"Reddit Post","permalink":"/r/sec/1"}}]}}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}

	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	t.Run("Success", func(t *testing.T) {
		data := w.fetchOSINTLinks(context.Background(), "CVE-2024-TEST")
		
		hn, ok := data["hn"].([]map[string]string)
		if !ok || len(hn) == 0 || hn[0]["title"] != "HN Story" {
			t.Errorf("expected HN story, got %v", data["hn"])
		}

		reddit, ok := data["reddit"].([]map[string]string)
		if !ok || len(reddit) == 0 || reddit[0]["title"] != "Reddit Post" {
			t.Errorf("expected Reddit post, got %v", data["reddit"])
		}
	})

	t.Run("RedditRateLimit", func(t *testing.T) {
		callCount := 0
		httpClientRateLimit := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "reddit.com") {
					callCount++
					if callCount == 1 {
						return &http.Response{
							StatusCode: http.StatusTooManyRequests,
							Header:     http.Header{"Retry-After": []string{"0"}},
							Body:       io.NopCloser(strings.NewReader("")),
						}, nil
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"data":{"children":[]}}`)),
					}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
			},
		}
		w2 := NewWorker(mock, rdb, &EmailSenderMock{}, httpClientRateLimit)
		
		_ = w2.fetchOSINTLinks(context.Background(), "CVE-2024-LIMIT")
		if callCount < 2 {
			t.Errorf("expected Reddit retry, but only called %d times", callCount)
		}
	})
}

func TestWorker_Intelligence(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			}, nil
		},
	}
	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	t.Run("EnrichMissingIntelligence", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT id, cve_id, description, configurations FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' ORDER BY cvss_score DESC, cisa_kev DESC LIMIT 1000")).
			WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "configurations"}).
				AddRow(1, "CVE-INTEL-1", "Test desc", []byte(`{}`)))
		
		// Note: The task actually calls updateTaskStats with "intelligence_enrichment"
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO worker_sync_stats (task_name, last_run) VALUES ($1, NOW()) ON CONFLICT (task_name) DO UPDATE SET last_run = NOW(), updated_at = NOW()")).
			WithArgs("intelligence_enrichment").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.enrichMissingIntelligence(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("syncIntelligencePeriodically", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w.syncIntelligencePeriodically(ctx)
	})

	t.Run("processIntelligence", func(t *testing.T) {
		// processIntelligence(ctx) - no second arg
		_ = w.processIntelligence(context.Background())
	})

	t.Run("updateSocialSentiment", func(t *testing.T) {
		cve := models.CVE{CVEID: "CVE-SENT-1", OSINTData: make(models.JSONBMap)}
		// Should just run without panicking
		w.updateSocialSentiment(context.Background(), &cve)
	})

	t.Run("detectDuplicates", func(t *testing.T) {
		cve := models.CVE{CVEID: "CVE-DUP-1", Description: "This is a duplicate of CVE-2023-0001", OSINTData: make(models.JSONBMap)}
		// Should just run without panicking
		w.detectDuplicates(context.Background(), &cve)
	})
}

func TestWorker_Health_Coverage(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	w := NewWorker(mock, rdb, &EmailSenderMock{}, &MockHTTPClient{})

	t.Run("UpdateTaskStats", func(t *testing.T) {
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO worker_sync_stats (task_name, last_run) VALUES ($1, NOW()) ON CONFLICT (task_name) DO UPDATE SET last_run = NOW(), updated_at = NOW()")).
			WithArgs("test_task").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.updateTaskStats(context.Background(), "test_task")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("WaitUntilNextRun", func(t *testing.T) {
		// Mock existing run
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats").
			WithArgs("wait_task").
			WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		
		w.waitUntilNextRun(ctx, "wait_task", 1*time.Hour, 0)
	})
}
