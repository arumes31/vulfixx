package worker

import (
	"context"
	"fmt"
	"log"
	"time"
)

func (w *Worker) startHealthCheckPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "health_check", 30*time.Minute, 1*time.Minute)
	w.checkWorkerHealth(ctx)

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

	tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync"}
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

			// Send alert to admin if configured and not recently alerted
			if w.AdminEmail != "" {
				w.alertMu.Lock()
				lastAlert := w.alertTimestamps[task]
				canAlert := time.Since(lastAlert) >= w.alertResendBackoff
				if canAlert {
					w.alertTimestamps[task] = time.Now()
				}
				w.alertMu.Unlock()

				if canAlert {
					_ = w.Mailer.SendEmail(w.AdminEmail, "Vulfixx Health Alert", msg)
				}
			}
		}
	}
	w.updateTaskStats(ctx, "health_check")
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

// waitUntilNextRun ensures that a task respects its interval across restarts.
// If the task ran recently, it sleeps until the interval has passed.
func (w *Worker) waitUntilNextRun(ctx context.Context, taskName string, interval time.Duration, defaultInitialDelay time.Duration) {
	var lastRun time.Time
	err := w.Pool.QueryRow(ctx, "SELECT last_run FROM worker_sync_stats WHERE task_name = $1", taskName).Scan(&lastRun)

	var sleepDuration time.Duration
	if err != nil {
		// Task never run or error, use default initial delay to spread load
		sleepDuration = defaultInitialDelay
	} else {
		nextRun := lastRun.Add(interval)
		sleepDuration = time.Until(nextRun)

		// If the app just started, we want at least some delay to let the system stabilize,
		// but not the full initial delay if it's already due.
		minStartupDelay := 10 * time.Second
		if sleepDuration < minStartupDelay {
			sleepDuration = minStartupDelay
		}
	}

	if sleepDuration > 0 {
		log.Printf("Worker: [%s] Persistent schedule: next run in %v", taskName, sleepDuration.Round(time.Second))
		timer := time.NewTimer(sleepDuration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
