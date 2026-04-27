package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"log"
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

	// Synchronization Tasks
	go w.fetchCVEsPeriodically(ctx)
	go w.fetchCISAKEVPeriodically(ctx)
	go w.syncEPSSPeriodically(ctx)
	go w.syncGitHubBuzzPeriodically(ctx)

	// Notification & Alert Processing
	go w.processAlerts(ctx)
	go w.processEmailVerification(ctx)
	go w.processEmailChange(ctx)
	go w.startWeeklySummaryTask(ctx)

	log.Println("Worker: All background goroutines started.")
	<-ctx.Done()
	log.Println("Worker: Stopping background tasks...")
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
