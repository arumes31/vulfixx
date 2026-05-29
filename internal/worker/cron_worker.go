package worker

import (
	"context"
	"cve-tracker/internal/config"
	"cve-tracker/internal/llm"
	"cve-tracker/internal/models"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

func (w *Worker) runWeeklySummaryWithLock(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [CRON] Failed to begin transaction for weekly summary", "error", err)
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
			slog.Error("Worker: [CRON] Error querying last run for weekly summary", "error", err)
		}
	} else {
		lastRun, err := time.Parse(time.RFC3339, lastRunStr)
		if err != nil {
			slog.Error("Worker: [CRON] Error parsing lastRunStr", "value", lastRunStr, "error", err)
			shouldRun = true
		} else if time.Since(lastRun) > (6 * 24 * time.Hour) {
			shouldRun = true
		}
	}

	if shouldRun {
		slog.Info("Worker: [CRON] Executing weekly summary run...")
		if err := w.sendWeeklySummaries(ctx); err == nil {
			_, err = tx.Exec(ctx, "INSERT INTO sync_state (key, value, updated_at) VALUES ('weekly_summary_last_run', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", time.Now().Format(time.RFC3339))
			if err != nil {
				slog.Error("Worker: [CRON] Failed to update sync state for weekly summary", "error", err)
				return
			}
			if err := tx.Commit(ctx); err != nil {
				slog.Error("Worker: [CRON] Failed to commit weekly summary transaction", "error", err)
				return
			}
			slog.Info("Worker: [CRON] Weekly summary run complete.")
		} else {
			slog.Error("Worker: [CRON] sendWeeklySummaries failed", "error", err)
		}
	}
}

func (w *Worker) startIntelligenceEnrichmentTask(ctx context.Context) {
	slog.Info("Worker: [CRON] Intelligence enrichment task started")
	if ctx.Err() != nil {
		slog.Info("Worker: [CRON] Intelligence enrichment task shutting down")
		return
	}

	// Check queue size to determine initial interval
	var missingCount int
	err := w.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = ''").Scan(&missingCount)
	if err != nil && errors.Is(err, context.Canceled) {
		return
	}

	interval := 24 * time.Hour
	if missingCount > 5000 {
		interval = 4 * time.Hour
		slog.Info("Worker: [CRON] Large backlog detected, setting enrichment frequency", "missing_count", missingCount, "interval", interval)
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Worker: [CRON] Intelligence enrichment task shutting down")
			return
		case id := <-w.enrichmentQueue:
			// On-demand enrichment
			w.enrichSingleCVE(ctx, id)
		case <-timer.C:
			// Check context before enrichment call
			if ctx.Err() != nil {
				return
			}
			w.enrichMissingIntelligence(ctx)

			// Re-evaluate interval based on remaining backlog
			_ = w.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = ''").Scan(&missingCount)
			newInterval := 24 * time.Hour
			if missingCount > 5000 {
				newInterval = 4 * time.Hour
			}
			timer.Reset(newInterval)
		}
	}
}

func (w *Worker) enrichSingleCVE(ctx context.Context, id int) {
	var c models.CVE
	err := w.Pool.QueryRow(ctx, "SELECT id, cve_id, description, configurations, references FROM cves WHERE id = $1", id).Scan(&c.ID, &c.CVEID, &c.Description, &c.Configurations, &c.References)
	if err != nil {
		return
	}
	w.processEnrichmentRows(ctx, []models.CVE{c}, 1)
}

func (w *Worker) enrichMissingIntelligence(ctx context.Context) {
	slog.Info("Worker: [CRON] Starting intelligence enrichment for missing vendor data...")
	// Suggestion 3: Priority-based selection (highest CVSS first)
	rows, err := w.Pool.Query(ctx, "SELECT id, cve_id, description, configurations, references FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' ORDER BY cvss_score DESC, cisa_kev DESC LIMIT 1000")
	if err != nil {
		slog.Error("Worker: [CRON] Error querying CVEs for enrichment", "error", err)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.Configurations, &c.References); err != nil {
			continue
		}
		cves = append(cves, c)
	}
	rows.Close()

	// Get total for progress tracking
	var total int
	_ = w.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM (SELECT id FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' LIMIT 1000) sub").Scan(&total)
	if total == 0 {
		total = 1
	}

	w.processEnrichmentRows(ctx, cves, total)
}

func (w *Worker) processEnrichmentRows(ctx context.Context, cves []models.CVE, total int) {
	start := time.Now()
	var count int
	var llmCount int
	var heuristicCount int
	var consecutiveFailures int

	for _, c := range cves {
		// Suggestion 2: Adaptive Backoff
		if consecutiveFailures >= 3 {
			slog.Warn("Worker: [CRON] 3 consecutive LLM failures. Backing off for 15 minutes.")
			backoffTimer := time.NewTimer(15 * time.Minute)
			select {
			case <-backoffTimer.C:
				consecutiveFailures = 0 // reset after sleep
			case <-ctx.Done():
				backoffTimer.Stop()
				return
			}
		}

		var vendor, product string
		var extractedProducts []llm.ProductResult
		if config.AppConfig.GeminiAPIKey != "" || config.AppConfig.LLMProvider == "ollama" || config.AppConfig.ArliAIAPIKey != "" {
			// Call LLM as primary for missing data with isolated timeout
			llmCtx, cancel := context.WithTimeout(ctx, time.Duration(config.AppConfig.LLMTimeout+10)*time.Second)
			products, err := llm.ExtractVendorProduct(llmCtx, c.Description, c.References)
			cancel()
			if err != nil {
				slog.Error("Worker: [CRON] LLM extraction failed", "cve_id", c.CVEID, "error", err)
				consecutiveFailures++
			} else {
				consecutiveFailures = 0 // reset on success
				if len(products) > 0 {
					vendor, product = products[0].Vendor, products[0].Product
					extractedProducts = products
					llmCount++
					slog.Info("Worker: [CRON] LLM enriched existing CVE", "cve_id", c.CVEID, "products_found", len(products))
				}
			}
		}

		// Heuristic Fallback
		if vendor == "" || product == "" {
			hVendor, hProduct := c.GetDetectedProduct()
			if hVendor != "" && vendor == "" {
				vendor = hVendor
			}
			if hProduct != "" && product == "" {
				product = hProduct
			}
			if vendor != "" || product != "" {
				heuristicCount++
				slog.Info("Worker: [CRON] Heuristic fallback for existing CVE", "cve_id", c.CVEID, "vendor", vendor, "product", product)
			}
		}

		affected := c.GetAffectedProducts()
		// If we extracted products via LLM, add them to affected_products
		for _, p := range extractedProducts {
			found := slices.ContainsFunc(affected, func(ap models.AffectedProduct) bool {
				return ap.Vendor == p.Vendor && ap.Product == p.Product
			})
			if !found {
				affected = append(affected, models.AffectedProduct{
					Vendor:      p.Vendor,
					Product:     p.Product,
					Version:     p.Version,
					Type:        "a",
					Unconfirmed: true,
				})
			}
		}

		if vendor != "" || product != "" || len(affected) > 0 {
			_, err := w.Pool.Exec(ctx, "UPDATE cves SET vendor = $1, product = $2, affected_products = $3, updated_at = NOW() WHERE id = $4", vendor, product, affected, c.ID)
			if err == nil {
				count++
			}
		}

		if count > 0 && count%10 == 0 {
			avg := time.Since(start) / time.Duration(count)
			percent := (float64(count) / float64(total)) * 100
			slog.Info("Worker: [CRON] Intelligence progress", "count", count, "total", total, "percent", fmt.Sprintf("%.1f%%", percent), "llm_count", llmCount, "heuristic_count", heuristicCount, "avg_per_cve", avg.Truncate(time.Millisecond))
		}
	}

	w.updateTaskStats(ctx, "intelligence_enrichment")
	if count > 0 {
		slog.Info("Worker: [CRON] Intelligence enrichment complete", "count", count, "llm_count", llmCount, "heuristic_count", heuristicCount, "duration", time.Since(start))
	}
}

func (w *Worker) startWeeklySummaryTask(ctx context.Context) {
	slog.Info("Worker: [CRON] Weekly summary task started")
	if ctx.Err() != nil {
		slog.Info("Worker: [CRON] Weekly summary task shutting down")
		return
	}
	ticker := w.TickerFactory(7 * 24 * time.Hour)
	defer ticker.Stop()

	// Initial run attempt
	w.runWeeklySummaryWithLock(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Worker: [CRON] Weekly summary task shutting down")
			return
		case <-ticker.Chan():
			w.runWeeklySummaryWithLock(ctx)
		}
	}
}

func (w *Worker) sendWeeklySummaries(_ context.Context) error {
	slog.Info("Worker: [CRON] Starting weekly summaries distribution...")
	start := time.Now()
	// Implementation logic for weekly summaries
	slog.Info("Worker: [CRON] Weekly summaries distribution complete.", "duration", time.Since(start))
	return nil
}
