package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/hibiken/asynq"
)

const (
	// UAIntel is used for core vulnerability data synchronization (OSV, GreyNoise, InTheWild).
	UAIntel = "Vulfixx-Threat-Intel/2.0"
	// UABot is used for general threat intelligence feeds (CISA, EPSS).
	UABot = "Vulfixx-Threat-Intel-Bot/1.0"
	// UASocialBot is used for scraping or searching social platforms (Reddit, Hacker News).
	UASocialBot = "Vulfixx/2.0 (Threat Intelligence Bot)"
	// UAGitHub is used specifically for GitHub API interactions.
	UAGitHub = "Vulfixx-Threat-Intel"
	// UABrowser is used for RSS feeds that might block non-browser agents.
	UABrowser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

type Worker struct {
	Pool               db.DBPool
	Redis              db.RedisProvider
	Mailer             EmailSender
	HTTP               HTTPClient
	AdminEmail         string
	alertTimestamps    map[string]time.Time
	alertMu            sync.Mutex
	alertResendBackoff time.Duration
	enrichmentQueue    chan int
	AsynqClient        *asynq.Client
	HNClient           HNClient
}

func NewWorker(pool db.DBPool, redis db.RedisProvider, mailer EmailSender, http HTTPClient) *Worker {
	w := &Worker{
		Pool:               pool,
		Redis:              redis,
		Mailer:             mailer,
		HTTP:               http,
		alertTimestamps:    make(map[string]time.Time),
		alertResendBackoff: 4 * time.Hour,
		enrichmentQueue:    make(chan int, 1000),
	}
	w.HNClient = NewHNClient(http)
	return w
}

// sendRequest is a helper to create and execute HTTP requests with a consistent User-Agent and basic error handling.
func (w *Worker) sendRequest(ctx context.Context, method, url string, userAgent string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Note: We don't check status codes here as some handlers (like OSV)
	// handle 404s specifically as "not found" rather than an error.
	return resp, nil
}

func (w *Worker) Start(ctx context.Context) {
	if ctx.Err() != nil {
		slog.Info("Worker: Context already cancelled, not starting background tasks.")
		return
	}
	slog.Info("Worker: Starting background tasks...")

	// Test LLM connectivity on startup if provider is configured
	go func() {
		testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		w.TestLLMConnectivity(testCtx)
	}()

	var wg sync.WaitGroup

	runTask := func(task func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task(ctx)
		}()
	}

	// Synchronization Tasks
	runTask(w.fetchCVEsPeriodically)
	runTask(w.fetchCISAKEVPeriodically)
	runTask(w.syncEPSSPeriodically)
	runTask(w.syncThreatIntelPeriodically)
	runTask(w.syncGitHubBuzzPeriodically)
	runTask(w.syncIntelligencePeriodically)
	runTask(w.syncGreyNoisePeriodically)
	runTask(w.syncOSVPeriodically)
	runTask(w.syncInTheWildPeriodically)
	runTask(w.syncAdvisoryRSSPeriodically)
	runTask(w.startHealthCheckPeriodically)

	// Notification & Alert Processing
	if w.AsynqClient != nil {
		runTask(func(ctx context.Context) { w.StartAsynqServer(ctx) })
	} else {
		// Fallback to legacy Redis queues for backwards compatibility / local tests
		runTask(w.processAlerts)
		runTask(w.processEmailVerification)
		runTask(w.processEmailChange)
		runTask(w.startEmailRetryPoller)
	}

	runTask(w.startWeeklySummaryTask)
	runTask(w.startIntelligenceEnrichmentTask)

	slog.Info("Worker: All background goroutines started.")
	<-ctx.Done()
	slog.Info("Worker: Stopping background tasks, waiting for goroutines to finish...")
	wg.Wait()
	slog.Info("Worker: All tasks gracefully stopped.")
}

func (w *Worker) enqueueAlertsForCVE(ctx context.Context, cve models.CVE) error {
	if cve.ID == 0 {
		var id int
		err := w.Pool.QueryRow(ctx, "SELECT id FROM cves WHERE cve_id = $1", cve.CVEID).Scan(&id)
		if err != nil {
			return fmt.Errorf("failed to get internal ID for CVE %s: %w", cve.CVEID, err)
		}
		cve.ID = id
	}

	alertJob, err := json.Marshal(cve)
	if err != nil {
		return fmt.Errorf("failed to marshal alert for %s: %w", cve.CVEID, err)
	}

	if w.AsynqClient != nil {
		task := asynq.NewTask("task:cve_alert", alertJob)
		_, err := w.AsynqClient.EnqueueContext(ctx, task)
		if err != nil {
			return fmt.Errorf("failed to enqueue asynq alert for %s: %w", cve.CVEID, err)
		}
		return nil
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		if err := w.Redis.LPush(ctx, "cve_alerts_queue", alertJob).Err(); err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return nil
	}

	return fmt.Errorf("failed to enqueue alert for %s after retries: %w", cve.CVEID, lastErr)
}
