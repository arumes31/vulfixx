package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

func (w *Worker) syncIntelligencePeriodically(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	w.waitUntilNextRun(ctx, "intelligence_sync", 2*time.Hour, 4*time.Minute)
	if err := w.processIntelligence(ctx); err != nil {
		slog.Error("Worker: Initial intelligence sync error", "error", err)
	}

	ticker := time.NewTicker(2 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Info("Worker: Starting Intelligence Sync (Social Sentiment & Duplicate Detection)...")
			if err := w.processIntelligence(ctx); err != nil {
				slog.Error("Worker: Intelligence sync error", "error", err)
			}
		}
	}
}

func (w *Worker) processIntelligence(ctx context.Context) error {
	// Fetch top 100 recent/critical CVEs to update intelligence for
	rows, err := w.Pool.Query(ctx, `
		SELECT id, cve_id, description, COALESCE(cvss_score, 0), osint_data, github_poc_count, cwe_id, published_date
		FROM cves 
		ORDER BY published_date DESC, id DESC LIMIT 100
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var osintJSON []byte
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &osintJSON, &c.GitHubPoCCount, &c.CWEID, &c.PublishedDate); err != nil {
			continue
		}
		_ = json.Unmarshal(osintJSON, &c.OSINTData)
		if c.OSINTData == nil {
			c.OSINTData = make(map[string]interface{})
		}
		cves = append(cves, c)
	}

	batch := &pgx.Batch{}
	for _, c := range cves {
		// 1. Social Sentiment (Reddit & HN)
		w.updateSocialSentiment(ctx, &c)

		// 2. Duplicate Detection (Simplified)
		w.detectDuplicates(ctx, &c)

		// Queue update
		osintData, _ := json.Marshal(c.OSINTData)
		batch.Queue("UPDATE cves SET osint_data = $1 WHERE id = $2", osintData, c.ID)

		// Throttle to avoid rate limits
		time.Sleep(500 * time.Millisecond)
	}

	if batch.Len() > 0 {
		tx, err := w.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for intelligence sync: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		br := tx.SendBatch(ctx, batch)
		if br != nil {
			for i := 0; i < batch.Len(); i++ {
				if _, err := br.Exec(); err != nil {
					slog.Error("Worker: Batch item failed in intelligence sync", "error", err)
				}
			}
			if err := br.Close(); err != nil {
				slog.Error("Worker: Failed to close batch results in intelligence sync", "error", err)
			}
		} else {
			// Fallback for mock drivers
			for _, c := range cves {
				osintData, _ := json.Marshal(c.OSINTData)
				_, err = tx.Exec(ctx, "UPDATE cves SET osint_data = $1 WHERE id = $2", osintData, c.ID)
				if err != nil {
					slog.Error("Worker: Fallback update failed in intelligence sync", "cve_id", c.CVEID, "error", err)
				}
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit intelligence sync batch: %w", err)
		}
	}

	w.updateTaskStats(ctx, "intelligence_sync")
	return nil
}

func (w *Worker) updateSocialSentiment(ctx context.Context, c *models.CVE) {
	osint := w.fetchOSINTLinks(ctx, c.CVEID)

	// Merge counts into OSINTData
	if c.OSINTData == nil {
		c.OSINTData = make(models.JSONBMap)
	}

	if hn, ok := osint["hn"]; ok {
		c.OSINTData["hn"] = hn
	}
	if hnMentions, ok := osint["hn_mentions"]; ok {
		c.OSINTData["hn_mentions"] = hnMentions
	}
	if reddit, ok := osint["reddit"]; ok {
		c.OSINTData["reddit"] = reddit
	}
	if redditMentions, ok := osint["reddit_mentions"]; ok {
		c.OSINTData["reddit_mentions"] = redditMentions
	}

	// Sentiment Score Calculation (Simplified Heat Score)
	hnCount, _ := c.OSINTData["hn_mentions"].(int)
	if hnc, ok := c.OSINTData["hn_mentions"].(float64); ok {
		hnCount = int(hnc)
	}

	redditCount, _ := c.OSINTData["reddit_mentions"].(int)
	if rc, ok := c.OSINTData["reddit_mentions"].(float64); ok {
		redditCount = int(rc)
	}

	githubCount := c.GitHubPoCCount

	heatScore := (float64(hnCount) * 2.0) + (float64(redditCount) * 1.5) + (float64(githubCount) * 5.0)
	c.OSINTData["heat_score"] = heatScore
}

func (w *Worker) detectDuplicates(ctx context.Context, c *models.CVE) {
	// Simple duplicate detection: Look for CVEs with similar descriptions published around the same time
	// or mentions of the same base vulnerability ID in description.

	if c.CWEID == "" || c.CWEID == "NVD-CWE-noinfo" {
		return
	}

	var duplicateIDs []string
	// Match CVSS within 0.5 tolerance and prefer closer scores
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE cwe_id = $1 AND id != $2 AND ABS(cvss_score - $3) <= 0.5 AND published_date > $4
		ORDER BY ABS(cvss_score - $3) ASC
		LIMIT 5
	`, c.CWEID, c.ID, c.CVSSScore, c.PublishedDate.AddDate(0, 0, -7))

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dupID string
			if err := rows.Scan(&dupID); err == nil {
				duplicateIDs = append(duplicateIDs, dupID)
			}
		}
	}

	if len(duplicateIDs) > 0 {
		c.OSINTData["similar_threats"] = duplicateIDs
	}
}
