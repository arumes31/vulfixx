package worker

import (
	"context"
	"fmt"
	"log"
	"time"
)

func (w *Worker) startHealthCheckPeriodically(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.checkWorkerHealth(ctx)
		}
	}
}

func (w *Worker) checkWorkerHealth(ctx context.Context) {
	log.Println("Worker: Running self-health checks...")

	tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync"}
	for _, task := range tasks {
		var lastRun time.Time
		err := w.Pool.QueryRow(ctx, "SELECT last_run FROM worker_sync_stats WHERE task_name = $1", task).Scan(&lastRun)
		
		if err != nil {
			log.Printf("Worker Health ALERT: Task '%s' has never run or status missing!", task)
			continue
		}

		threshold := 26 * time.Hour
		if task == "nvd_sync" {
			threshold = 8 * time.Hour
		}

		if time.Since(lastRun) > threshold {
			msg := fmt.Sprintf("CRITICAL: Worker task '%s' has not run since %v (more than %v ago)!", task, lastRun.Format(time.RFC822), threshold)
			log.Println(msg)
			
			// Send alert to admin if configured
			_ = w.Mailer.SendEmail("admin@example.com", "Vulfixx Health Alert", msg)
		}
	}
}

func (w *Worker) updateTaskStats(ctx context.Context, taskName string) {
	_, err := w.Pool.Exec(ctx, `
		INSERT INTO worker_sync_stats (task_name, last_run) 
		VALUES ($1, NOW()) 
		ON CONFLICT (task_name) DO UPDATE SET last_run = NOW(), updated_at = NOW()
	`, taskName)
	if err != nil {
		log.Printf("Worker: Failed to update stats for %s: %v", taskName, err)
	}
}
