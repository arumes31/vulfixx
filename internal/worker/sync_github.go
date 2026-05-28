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

		const maxGHRetries = 3
		var ghResp struct {
			TotalCount int `json:"total_count"`
		}
		fetchOK := false
		for attempt := 0; attempt < maxGHRetries; attempt++ {
			githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
			headers := map[string]string{"Accept": "application/vnd.github.v3+json"}
			if token := os.Getenv("GITHUB_TOKEN"); token != "" {
				headers["Authorization"] = "token " + token
			}
			resp, err := w.sendRequest(ctx, "GET", githubURL, UAGitHub, headers)
			if err != nil {
				slog.Error("Worker: [ERROR] Failed to fetch GitHub buzz", "cve_id", cveID, "error", err)
				waitDur := time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDur):
				}
				continue // retry
			}
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
				_ = resp.Body.Close()
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
				// Clamp to a safe maximum
				maxWait := 5 * time.Minute
				if waitDur > maxWait {
					waitDur = maxWait
				}
				slog.Warn("Worker: [WARN] GitHub rate limited", "cve_id", cveID, "wait_duration", waitDur, "attempt", attempt+1, "max_retries", maxGHRetries)
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDur):
				}
				continue // retry
			}
			if resp.StatusCode >= 500 {
				slog.Warn("Worker: [WARN] GitHub API returned server error", "status", resp.StatusCode, "cve_id", cveID)
				_ = resp.Body.Close()
				waitDur := time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDur):
				}
				continue // retry
			}
			if resp.StatusCode != http.StatusOK {
				slog.Warn("Worker: [WARN] GitHub API returned non-OK status", "status", resp.StatusCode, "cve_id", cveID)
				_ = resp.Body.Close()
				continue CVELoop
			}
			err = json.NewDecoder(resp.Body).Decode(&ghResp)
			_ = resp.Body.Close()
			if err != nil {
				slog.Error("Worker: [ERROR] Failed to decode GitHub response", "cve_id", cveID, "error", err)
				waitDur := time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDur):
				}
				continue // retry
			}
			fetchOK = true
			break // success
		}
		if fetchOK {
			_, err := w.Pool.Exec(ctx, "UPDATE cves SET github_poc_count = $1 WHERE cve_id = $2", ghResp.TotalCount, cveID)
			if err != nil {
				slog.Error("Worker: [ERROR] Failed to update GitHub buzz in DB", "cve_id", cveID, "error", err)
			}
		} else {
			slog.Warn("Worker: [WARN] Skipping DB update for CVE — all GitHub retries failed", "cve_id", cveID)
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
