package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"
)

func (w *Worker) syncIntelligencePeriodically(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	w.waitUntilNextRun(ctx, "intelligence_sync", 2*time.Hour, 4*time.Minute)
	w.runWithLock(ctx, "intelligence_sync", 30*time.Minute, func(c context.Context) {
		if err := w.processIntelligence(c); err != nil {
			slog.Error("Worker: Initial intelligence sync error", "error", err)
		}
	})
	if w.OnIntelligenceSyncDone != nil {
		w.OnIntelligenceSyncDone()
	}

	ticker := w.TickerFactory(2 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			slog.Info("Worker: Starting Intelligence Sync (Social Sentiment & Duplicate Detection)...")
			w.runWithLock(ctx, "intelligence_sync", 30*time.Minute, func(c context.Context) {
				if err := w.processIntelligence(c); err != nil {
					slog.Error("Worker: Intelligence sync error", "error", err)
				}
			})
			if w.OnIntelligenceSyncDone != nil {
				w.OnIntelligenceSyncDone()
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

	var cves []*models.CVE
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
		cves = append(cves, &c)
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for _, c := range cves {
		c := c // shadow for goroutine
		g.Go(func() error {
			// 1. Social Sentiment (Reddit & HN)
			w.updateSocialSentiment(gCtx, c)

			// 2. Duplicate Detection (Simplified)
			w.detectDuplicates(gCtx, c)

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	if len(cves) > 0 {
		tx, err := w.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for intelligence sync: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		query := "UPDATE cves SET osint_data = $1 WHERE id = $2"
		batch := &pgx.Batch{}
		for _, c := range cves {
			osintData, _ := json.Marshal(c.OSINTData)
			batch.Queue(query, osintData, c.ID)
		}

		br := tx.SendBatch(ctx, batch)
		if br != nil {
			defer br.Close()
			for i := 0; i < batch.Len(); i++ {
				if _, err := br.Exec(); err != nil {
					slog.Error("Worker: Batch item failed in intelligence sync", "error", err)
				}
			}
		} else {
			// Fallback for pgxmock test compatibility
			for _, c := range cves {
				osintData, _ := json.Marshal(c.OSINTData)
				if _, err := tx.Exec(ctx, query, osintData, c.ID); err != nil {
					slog.Error("Worker: Intelligence sync update failed", "id", c.ID, "error", err)
				}
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction for intelligence sync: %w", err)
		}
	}

	w.updateTaskStats(ctx, "intelligence_sync")
	return nil
}

func (w *Worker) updateSocialSentiment(ctx context.Context, c *models.CVE) {
	// Hacker News Mentions
	if count, _, err := w.fetchHNMentions(ctx, c.CVEID); err == nil {
		c.OSINTData["hn_mentions"] = count
	}

	// Reddit Mentions
	if count, _, err := w.fetchRedditMentions(ctx, c.CVEID); err == nil {
		c.OSINTData["reddit_mentions"] = count
	}

	// Sentiment Score Calculation (Simplified Heat Score)
	var hnMentions, redditMentions float64
	if val, ok := c.OSINTData["hn_mentions"].(int); ok {
		hnMentions = float64(val)
	}
	if val, ok := c.OSINTData["reddit_mentions"].(int); ok {
		redditMentions = float64(val)
	}

	// Calculate a simple heat score
	heatScore := (hnMentions * 2.0) + redditMentions + (float64(c.GitHubPoCCount) * 5.0)
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

func (w *Worker) fetchHNMentions(ctx context.Context, cveID string) (int, []map[string]string, error) {
	if w.HNClient == nil {
		return 0, nil, fmt.Errorf("HNClient not initialized")
	}
	w.initLimiters()
	if err := w.HNLimiter.Wait(ctx); err != nil {
		return 0, nil, err
	}
	return w.HNClient.FetchMentions(ctx, cveID)
}

func (w *Worker) fetchRedditMentions(ctx context.Context, cveID string) (int, []map[string]string, error) {
	if !isValidCVEID(cveID) {
		return 0, nil, fmt.Errorf("invalid CVE ID: %s", cveID)
	}

	w.initLimiters()
	if err := w.RedditLimiter.Wait(ctx); err != nil {
		return 0, nil, err
	}
	encodedID := url.QueryEscape(cveID)
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=new&limit=10", encodedID)

	resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
		Label:       "Reddit Mention Fetch",
	}, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", redditURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "vulfixx:cve-tracker:v1.0 (by /u/vulfixx)")
		return req, nil
	})

	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("reddit api returned status %d", resp.StatusCode)
	}

	// Protect against large responses
	lr := io.LimitReader(resp.Body, 1*1024*1024)
	var result struct {
		Data struct {
			Children []struct {
				Data map[string]interface{} `json:"data"`
			} `json:"children"`
		} `json:"data"`
	}

	if err := json.NewDecoder(lr).Decode(&result); err != nil {
		return 0, nil, err
	}

	var mentions []map[string]string
	for _, child := range result.Data.Children {
		mention := make(map[string]string)
		if title, ok := child.Data["title"].(string); ok {
			mention["title"] = title
		}
		if permalink, ok := child.Data["permalink"].(string); ok {
			if !isValidRedditPermalink(permalink) {
				continue
			}
			mention["url"] = "https://reddit.com" + permalink
		}
		mentions = append(mentions, mention)
	}

	return len(mentions), mentions, nil
}
