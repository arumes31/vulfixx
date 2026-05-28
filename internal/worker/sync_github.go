package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	githubSyncDelay = 7 * time.Second
)

func (w *Worker) syncGitHubBuzzPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "github_buzz_sync", 4*time.Hour, 1*time.Minute)
	w.syncGitHubBuzz(ctx)

	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncGitHubBuzz(ctx)
		}
	}
}

func (w *Worker) syncGitHubBuzz(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting GitHub Social Buzz synchronization...")

	rows, err := w.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE published_date > NOW() - INTERVAL '14 days' ORDER BY published_date DESC")
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch CVEs for GitHub sync", "error", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			slog.Error("Worker: Error scanning CVE row for GitHub sync", "error", err)
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Worker: [ERROR] Row iteration error in syncGitHubBuzz", "error", err)
	}

	start := time.Now()
CVELoop:
	for _, cveID := range cveIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var ghResp struct {
			TotalCount int `json:"total_count"`
		}

		githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
		resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
			MaxRetries:  3,
			MaxWait:     5 * time.Minute,
			ShouldRetry: githubShouldRetry,
			Label:       "GitHub Buzz Sync",
		}, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, "GET", githubURL, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "Vulfixx-Threat-Intel")
			if token := os.Getenv("GITHUB_TOKEN"); token != "" {
				req.Header.Set("Authorization", "token "+token)
			}
			return req, nil
		})

		if err != nil {
			slog.Error("Worker: [ERROR] GitHub request failed after retries", "cve_id", cveID, "error", err)
			continue CVELoop
		}
		if resp == nil {
			continue CVELoop
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			slog.Warn("Worker: [WARN] GitHub API returned non-OK status", "status", resp.StatusCode, "cve_id", cveID)
			continue CVELoop
		}

		if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
			slog.Error("Worker: [ERROR] Failed to decode GitHub response", "cve_id", cveID, "error", err)
			continue CVELoop
		}

		_, err = w.Pool.Exec(ctx, "UPDATE cves SET github_poc_count = $1 WHERE cve_id = $2", ghResp.TotalCount, cveID)
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to update GitHub buzz in DB", "cve_id", cveID, "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(githubSyncDelay):
		}
	}
	w.updateTaskStats(ctx, "github_buzz_sync")
	slog.Info("Worker: [SYNC] GitHub Social Buzz synchronization complete.", "duration", time.Since(start))
}

func githubShouldRetry(resp *http.Response, err error, attempt int) (bool, time.Duration) {
	if err != nil {
		return true, time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
	}
	if resp == nil {
		return false, 0
	}

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		var waitDur time.Duration
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
				waitDur = time.Until(time.Unix(ts, 0))
				if waitDur < 0 {
					waitDur = 0
				}
			}
		}
		if waitDur == 0 {
			waitDur = time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
		}
		return true, waitDur
	}

	if resp.StatusCode >= 500 {
		return true, time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
	}

	return false, 0
}
