package worker

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"
)

func (w *Worker) runWeeklySummaryWithLock(ctx context.Context) {
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Worker: [CRON] Failed to begin transaction: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	// 55667788 is an arbitrary lock ID for weekly summary
	err = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(55667788)").Scan(&locked)
	if err != nil || !locked {
		return
	}

	var lastRunStr string
	err = tx.QueryRow(ctx, "SELECT value FROM sync_state WHERE key = 'weekly_summary_last_run'").Scan(&lastRunStr)
	shouldRun := false
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			shouldRun = true
		} else {
			log.Printf("Worker: [CRON] Error querying last run: %v", err)
		}
	} else {
		lastRun, err := time.Parse(time.RFC3339, lastRunStr)
		if err != nil {
			log.Printf("Worker: [CRON] Error parsing lastRunStr: %v", err)
			shouldRun = true
		} else if time.Since(lastRun) > (6 * 24 * time.Hour) {
			shouldRun = true
		}
	}

	if shouldRun {
		log.Println("Worker: [CRON] Executing weekly summary run...")
		if err := w.sendWeeklySummaries(ctx); err == nil {
			_, err = tx.Exec(ctx, "INSERT INTO sync_state (key, value, updated_at) VALUES ('weekly_summary_last_run', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", time.Now().Format(time.RFC3339))
			if err != nil {
				log.Printf("Worker: [CRON] Failed to update sync state: %v", err)
				return
			}
			if err := tx.Commit(ctx); err != nil {
				log.Printf("Worker: [CRON] Failed to commit weekly summary: %v", err)
				return
			}
			log.Println("Worker: [CRON] Weekly summary run complete.")
		} else {
			log.Printf("Worker: [CRON] sendWeeklySummaries failed: %v", err)
		}
	}
}

func (w *Worker) startWeeklySummaryTask(ctx context.Context) {
	log.Println("Worker: [CRON] Weekly summary task started")
	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()

	// Initial run attempt
	w.runWeeklySummaryWithLock(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("Worker: [CRON] Weekly summary task shutting down")
			return
		case <-ticker.C:
			w.runWeeklySummaryWithLock(ctx)
		}
	}
}

func (w *Worker) sendWeeklySummaries(_ context.Context) error {
	log.Println("Worker: [CRON] Starting weekly summaries distribution...")
	start := time.Now()
	// Implementation logic for weekly summaries
	log.Printf("Worker: [CRON] Weekly summaries distribution complete. Duration: %v", time.Since(start))
	return nil
}
