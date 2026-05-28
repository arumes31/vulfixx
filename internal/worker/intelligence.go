package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
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
	// Hacker News Mentions
	if count, _, err := w.fetchHNMentions(ctx, c.CVEID); err == nil {
		c.OSINTData["hn_mentions"] = count
	}

	// Reddit Mentions
	if count, _, err := w.fetchRedditMentions(ctx, c.CVEID); err == nil {
		c.OSINTData["reddit_mentions"] = count
	}

	// Sentiment Score Calculation (Simplified Heat Score)
	hnCount, _ := c.OSINTData["hn_mentions"].(int)
	redditCount, _ := c.OSINTData["reddit_mentions"].(int)
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

func (w *Worker) fetchHNMentions(ctx context.Context, cveID string) (int, []map[string]string, error) {
	if w.HNClient == nil {
		return 0, nil, fmt.Errorf("HNClient not initialized")
	}
	return w.HNClient.FetchMentions(ctx, cveID)
}

func (w *Worker) fetchRedditMentions(ctx context.Context, cveID string) (int, []map[string]string, error) {
	encodedID := url.QueryEscape(cveID)
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=new&limit=10", encodedID)

	var resp *http.Response
	var err error
	for retries := 0; retries < 3; retries++ {
		req, errReq := http.NewRequestWithContext(ctx, "GET", redditURL, nil)
		if errReq != nil {
			return 0, nil, errReq
		}
		req.Header.Set("User-Agent", "Vulfixx/2.0 (Threat Intelligence Bot)")

		resp, err = w.HTTP.Do(req)
		if err != nil {
			return 0, nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			waitTime := 5 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, errSec := strconv.Atoi(ra); errSec == nil {
					waitTime = time.Duration(seconds) * time.Second
				}
			}
			slog.Warn("Worker: Reddit rate limited", "cve_id", cveID, "retry_after", waitTime)
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(waitTime):
				continue
			}
		}
		break
	}

	if resp == nil {
		return 0, nil, fmt.Errorf("Reddit API returned nil response")
	}

	if resp.StatusCode != http.StatusOK {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return 0, nil, fmt.Errorf("Reddit API returned status %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	var rResp struct {
		Data struct {
			Children []struct {
				Data struct {
					Title     string `json:"title"`
					Permalink string `json:"permalink"`
				} `json:"data"`
			} `json:"children"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rResp); err != nil {
		return 0, nil, err
	}

	links := []map[string]string{}
	for _, child := range rResp.Data.Children {
		redditLink := fmt.Sprintf("https://www.reddit.com%s", child.Data.Permalink)
		links = append(links, map[string]string{"title": child.Data.Title, "url": redditLink})
	}

	return len(links), links, nil
}
