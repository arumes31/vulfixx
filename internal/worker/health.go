package worker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"cve-tracker/internal/config"
	"cve-tracker/internal/llm"
)

func (w *Worker) startHealthCheckPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "health_check", 30*time.Minute, 1*time.Minute)
	w.runWithLock(ctx, "health_check", 5*time.Minute, w.checkWorkerHealth)

	ticker := w.TickerFactory(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "health_check", 5*time.Minute, w.checkWorkerHealth)
			if w.OnHealthCheckDone != nil {
				w.OnHealthCheckDone()
			}
		}
	}
}

func (w *Worker) checkWorkerHealth(ctx context.Context) {
	slog.Info("Worker: Running self-health checks...")

	tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync", "inthewild_sync", "threat_intel_sync", "advisory_rss_sync", "intelligence_sync", "intelligence_enrichment", "health_check"}
	w.checkNotificationHealth(ctx)

	rows, err := w.Pool.Query(ctx, "SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY($1)", tasks)
	if err != nil {
		slog.Error("Worker Health ALERT: Failed to query sync stats", "error", err)
		return
	}
	defer rows.Close()

	lastRuns := make(map[string]time.Time)
	for rows.Next() {
		var tn string
		var lr time.Time
		if err := rows.Scan(&tn, &lr); err != nil {
			slog.Error("Worker Health ALERT: Failed to scan sync stats", "error", err)
			return
		}
		lastRuns[tn] = lr
	}
	if err := rows.Err(); err != nil {
		slog.Error("Worker Health ALERT: Row iteration error", "error", err)
		return
	}

	for _, task := range tasks {
		lastRun, ok := lastRuns[task]

		if !ok {
			slog.Warn("Worker Health ALERT: Task has never run or status is missing", "task", task)
			continue
		}

		threshold := 26 * time.Hour
		switch task {
		case "nvd_sync":
			threshold = 8 * time.Hour
		case "intelligence_sync":
			threshold = 6 * time.Hour
		case "github_buzz_sync", "greynoise_sync":
			threshold = 12 * time.Hour
		case "health_check":
			threshold = 1 * time.Hour
		}

		if time.Since(lastRun) > threshold {
			msg := fmt.Sprintf("CRITICAL: Worker task '%s' has not run since %v (more than %v ago)!", task, lastRun.Format(time.RFC822), threshold)
			slog.Error("CRITICAL System Event Detected", "task", task, "last_run", lastRun, "threshold", threshold)

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
					baseURL := os.Getenv("BASE_URL")
					if baseURL == "" {
						baseURL = "http://localhost:8080"
						slog.Warn("Worker Health ALERT: BASE_URL environment variable is unset. Falling back to default.", "fallback", baseURL)
					}
					contentTmpl := `
						<div style="background-color: #ff4d4d1a; padding: 20px; border-radius: 16px; border: 1px solid #ff4d4d33; color: #ff4d4d; margin-bottom: 20px;">
							<strong>⚠️ Critical System Event</strong>
						</div>
						<p style="font-size: 16px; line-height: 1.6;">The following health event was detected in the Vulfixx environment:</p>
						<div style="background-color: #1c2026; padding: 20px; border-radius: 16px; border: 1px solid #232931; font-family: monospace; font-size: 14px;">
							{{.Msg}}
						</div>
						<div style="margin-top: 30px; text-align: center;">
							<a href="{{.BaseURL}}/dashboard" class="btn">Access Command Center</a>
						</div>
					`

					data := struct {
						Msg     string
						BaseURL string
					}{
						Msg:     msg,
						BaseURL: baseURL,
					}

					body, err := RenderEmailTemplate("Vulfixx Health Alert", contentTmpl, data)
					if err != nil {
						slog.Error("Worker Health: Failed to render health alert email template", "error", err)
						continue
					}

					if err := w.Mailer.SendEmail(w.AdminEmail, "Vulfixx Health Alert", body); err != nil {
						slog.Error("Worker: Failed to send health alert email", "to", w.AdminEmail, "error", err)
					}
				}
			}
		}
	}
	w.updateTaskStats(ctx, "health_check")
}

func (w *Worker) TestLLMConnectivity(ctx context.Context) {
	if config.AppConfig.LLMProvider == "" {
		return
	}
	slog.Info("Worker: Testing LLM connectivity", "provider", config.AppConfig.LLMProvider)

	testDescription := "This is a test description for a vulnerability in a hypothetical product called Vulfixx version 1.0.0."
	start := time.Now()
	products, err := llm.ExtractVendorProduct(ctx, testDescription, nil)
	if err != nil {
		slog.Error("Worker: [LLM TEST FAILED]", "error", err, "duration", time.Since(start))
		return
	}

	if len(products) > 0 {
		slog.Info("Worker: [LLM TEST SUCCESS]", "products_found", len(products), "primary_vendor", products[0].Vendor, "primary_product", products[0].Product, "duration", time.Since(start))
	} else {
		slog.Warn("Worker: [LLM TEST WARNING] LLM reachable but returned no products for test description", "duration", time.Since(start))
	}
}

func (w *Worker) checkNotificationHealth(ctx context.Context) {
	var failureCount int
	err := w.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM notification_delivery_logs 
		WHERE status = 'failure' AND delivery_time > NOW() - INTERVAL '24 hours'
	`).Scan(&failureCount)
	if err != nil {
		slog.Error("Worker Health ERROR: notification health query failed", "error", err)
		return
	}
	if failureCount > 0 {
		slog.Warn("Worker Health WARNING: notification delivery failures detected", "failure_count", failureCount, "period", "last 24 hours")
	}
}

func (w *Worker) updateTaskStats(ctx context.Context, taskName string) {
	_, err := w.Pool.Exec(ctx, `
		INSERT INTO worker_sync_stats (task_name, last_run) 
		VALUES ($1, NOW()) 
		ON CONFLICT (task_name) DO UPDATE SET last_run = NOW(), updated_at = NOW()
	`, taskName)
	if err != nil {
		slog.Error("Worker: Failed to update stats for task", "task", taskName, "error", err)
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
		if os.Getenv("GO_TEST") == "true" {
			minStartupDelay = 0
		}
		if sleepDuration < minStartupDelay {
			sleepDuration = minStartupDelay
		}
	}

	if sleepDuration > 0 {
		slog.Info("Worker: Persistent schedule", "task", taskName, "next_run_in", sleepDuration.Round(time.Second))
		timer := w.TimerFactory(sleepDuration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.Chan():
		}
	}
}
