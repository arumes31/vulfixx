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
	"sync"
	"time"

	"golang.org/x/time/rate"
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

	// Rate limiting: GitHub Search API
	// Authenticated: 30 requests per minute
	// Unauthenticated: 10 requests per minute
	var limit rate.Limit
	if os.Getenv("GO_TEST") == "true" {
		limit = rate.Inf
	} else if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		limit = rate.Every(time.Minute / 30)
	} else {
		limit = rate.Every(time.Minute / 10)
	}
	limiter := rate.NewLimiter(limit, 1)

	const numWorkers = 5
	cveChan := make(chan string, len(cveIDs))
	for _, id := range cveIDs {
		cveChan <- id
	}
	close(cveChan)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cveID := range cveChan {
				if err := limiter.Wait(ctx); err != nil {
					return
				}
				w.fetchAndUpdateGitHubBuzz(ctx, cveID)
			}
		}()
	}
	wg.Wait()

	w.updateTaskStats(ctx, "github_buzz_sync")
	slog.Info("Worker: [SYNC] GitHub Social Buzz synchronization complete.", "duration", time.Since(start))
}

func (w *Worker) fetchAndUpdateGitHubBuzz(ctx context.Context, cveID string) {
	const maxGHRetries = 3
	var ghResp struct {
		TotalCount int `json:"total_count"`
	}
	fetchOK := false
	for attempt := 0; attempt < maxGHRetries; attempt++ {
		githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
		req, err := http.NewRequestWithContext(ctx, "GET", githubURL, nil)
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to create GitHub request", "cve_id", cveID, "error", err)
			return
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel")
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "token "+token)
		}
		resp, err := w.HTTP.Do(req)
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
			return
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
}
