package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
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
}

func NewWorker(pool db.DBPool, redis db.RedisProvider, mailer EmailSender, http HTTPClient) *Worker {
	return &Worker{
		Pool:               pool,
		Redis:              redis,
		Mailer:             mailer,
		HTTP:               http,
		alertTimestamps:    make(map[string]time.Time),
		alertResendBackoff: 4 * time.Hour,
	}
}

func (w *Worker) Start(ctx context.Context) {
	log.Println("Worker: Starting background tasks...")
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
	runTask(w.syncGitHubBuzzPeriodically)
	runTask(w.syncIntelligencePeriodically)
	runTask(w.startHealthCheckPeriodically)

	// Notification & Alert Processing
	runTask(w.processAlerts)
	runTask(w.processEmailVerification)
	runTask(w.processEmailChange)
	runTask(w.startEmailRetryPoller)
	runTask(w.startWeeklySummaryTask)

	log.Println("Worker: All background goroutines started.")
	<-ctx.Done()
	log.Println("Worker: Stopping background tasks, waiting for goroutines to finish...")
	wg.Wait()
	log.Println("Worker: All tasks gracefully stopped.")
}

func (w *Worker) enqueueAlertsForCVE(ctx context.Context, cve models.CVE) error {
	// First, get the internal ID for the CVE as it might be needed by the alert processor
	var id int
	err := w.Pool.QueryRow(ctx, "SELECT id FROM cves WHERE cve_id = $1", cve.CVEID).Scan(&id)
	if err != nil {
		return fmt.Errorf("failed to get internal ID for CVE %s: %w", cve.CVEID, err)
	}
	cve.ID = id

	alertJob, err := json.Marshal(cve)
	if err != nil {
		return fmt.Errorf("failed to marshal alert for %s: %w", cve.CVEID, err)
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
