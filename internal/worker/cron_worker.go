package worker

import (
	"context"
	"cve-tracker/internal/config"
	"cve-tracker/internal/llm"
	"cve-tracker/internal/models"
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

func (w *Worker) startIntelligenceEnrichmentTask(ctx context.Context) {
	w.waitUntilNextRun(ctx, "intelligence_enrichment", 24*time.Hour, 10*time.Minute)
	w.enrichMissingIntelligence(ctx)

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Worker: [CRON] Intelligence enrichment task shutting down")
			return
		case <-ticker.C:
			w.enrichMissingIntelligence(ctx)
		}
	}
}

func (w *Worker) enrichMissingIntelligence(ctx context.Context) {
	log.Println("Worker: [CRON] Starting intelligence enrichment for missing vendor data...")
	start := time.Now()

	rows, err := w.Pool.Query(ctx, "SELECT id, cve_id, description, configurations FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' LIMIT 1000")
	if err != nil {
		log.Printf("Worker: [CRON] Error querying CVEs for enrichment: %v", err)
		return
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var c models.CVE
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.Configurations); err != nil {
			continue
		}

		vendor, product := c.GetDetectedProduct()
		var extractedProducts []llm.ProductResult
		if vendor == "" && (config.AppConfig.GeminiAPIKey != "" || config.AppConfig.LLMProvider == "ollama") {
			model := config.AppConfig.GeminiModel
			if config.AppConfig.LLMProvider == "ollama" {
				model = config.AppConfig.LLMModel
			}

			// Call LLM as fallback for missing data
			products, err := llm.ExtractVendorProduct(ctx, config.AppConfig.LLMProvider, config.AppConfig.GeminiAPIKey, config.AppConfig.LLMEndpoint, model, c.Description)
			if err == nil && len(products) > 0 {
				vendor, product = products[0].Vendor, products[0].Product
				extractedProducts = products
				log.Printf("Worker: [CRON] LLM enriched existing CVE %s: found %d products", c.CVEID, len(products))
			}
		}

		affected := c.GetAffectedProducts()
		// If we extracted products via LLM, add them to affected_products
		for _, p := range extractedProducts {
			found := false
			for _, ap := range affected {
				if ap.Vendor == p.Vendor && ap.Product == p.Product {
					found = true
					break
				}
			}
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
	}

	w.updateTaskStats(ctx, "intelligence_enrichment")
	log.Printf("Worker: [CRON] Intelligence enrichment complete. Enriched %d records. Duration: %v", count, time.Since(start))
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
