package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"log"
	"sync"
)

type Worker struct {
	Pool   db.DBPool
	Redis  db.RedisProvider
	Mailer EmailSender
	HTTP   HTTPClient
}

func NewWorker(pool db.DBPool, redis db.RedisProvider, mailer EmailSender, http HTTPClient) *Worker {
	return &Worker{
		Pool:   pool,
		Redis:  redis,
		Mailer: mailer,
		HTTP:   http,
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

func (w *Worker) enqueueAlertsForCVE(ctx context.Context, cve models.CVE) {
	// First, get the internal ID for the CVE as it might be needed by the alert processor
	var id int
	err := w.Pool.QueryRow(ctx, "SELECT id FROM cves WHERE cve_id = $1", cve.CVEID).Scan(&id)
	if err != nil {
		log.Printf("Worker: Failed to get internal ID for CVE %s for alert: %v", cve.CVEID, err)
		return
	}
	cve.ID = id

	alertJob, err := json.Marshal(cve)
	if err != nil {
		log.Printf("Worker: Failed to marshal alert for %s: %v", cve.CVEID, err)
		return
	}

	if err := w.Redis.LPush(ctx, "cve_alerts_queue", alertJob).Err(); err != nil {
		log.Printf("Worker: Failed to enqueue alert for %s: %v", cve.CVEID, err)
	}
}
