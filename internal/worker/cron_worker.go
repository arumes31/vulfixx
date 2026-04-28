package worker

import (
	"context"
	"log"
	"time"
)

func (w *Worker) startWeeklySummaryTask(ctx context.Context) {
	log.Println("Worker: [CRON] Weekly summary task started")
	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()

	// Run once immediately on startup if it hasn't run in the last 6 days
	var lastRunStr string
	err := w.Pool.QueryRow(ctx, "SELECT value FROM sync_state WHERE key = 'weekly_summary_last_run'").Scan(&lastRunStr)
	shouldRun := false
	if err != nil {
		shouldRun = true // First time or error
	} else {
		lastRun, _ := time.Parse(time.RFC3339, lastRunStr)
		if time.Since(lastRun) > (6 * 24 * time.Hour) {
			shouldRun = true
		}
	}

	if shouldRun {
		log.Println("Worker: [CRON] Executing initial weekly summary run...")
		w.sendWeeklySummaries(ctx)
		_, _ = w.Pool.Exec(ctx, "INSERT INTO sync_state (key, value, updated_at) VALUES ('weekly_summary_last_run', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", time.Now().Format(time.RFC3339))
		log.Println("Worker: [CRON] Initial weekly summary run complete.")
	} else {
		log.Println("Worker: [CRON] Weekly summary recently executed, skipping initial run.")
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Worker: [CRON] Weekly summary task shutting down")
			return
		case <-ticker.C:
			log.Println("Worker: [CRON] Executing weekly summary run...")
			w.sendWeeklySummaries(ctx)
			log.Println("Worker: [CRON] Weekly summary run complete.")
		}
	}
}

func (w *Worker) sendWeeklySummaries(ctx context.Context) {
	log.Println("Worker: [CRON] Starting weekly summaries distribution...")
	start := time.Now()
	// Implementation logic for weekly summaries
	log.Printf("Worker: [CRON] Weekly summaries distribution complete. Duration: %v", time.Since(start))
}
