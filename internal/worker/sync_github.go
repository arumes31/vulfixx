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
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
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

type githubUpdateItem struct {
	cveID      string
	totalCount int
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

	if len(cveIDs) == 0 {
		return
	}

	start := time.Now()

	// Respect GitHub Search API rate limits (originally 7s delay between requests)
	limiter := rate.NewLimiter(rate.Every(githubSyncDelay), 1)
	g, gCtx := errgroup.WithContext(ctx)

	cveChan := make(chan string)
	updateChan := make(chan githubUpdateItem, 50)
	var processedCount int64

	// Result collector goroutine
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		var pendingUpdates []githubUpdateItem
		for up := range updateChan {
			pendingUpdates = append(pendingUpdates, up)
			if len(pendingUpdates) >= 50 {
				w.updateGitHubBatch(ctx, pendingUpdates)
				pendingUpdates = nil
			}
		}
		if len(pendingUpdates) > 0 {
			w.updateGitHubBatch(ctx, pendingUpdates)
		}
	}()

	// Start concurrent workers
	numWorkers := 5
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			for cveID := range cveChan {
				if err := limiter.Wait(gCtx); err != nil {
					return err
				}

				var ghResp struct {
					TotalCount int `json:"total_count"`
				}

				githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
				resp, err := DoWithRetry(gCtx, w.HTTP, RetryConfig{
					MaxRetries:  3,
					MaxWait:     5 * time.Minute,
					ShouldRetry: githubShouldRetry,
					Label:       "GitHub Buzz Sync",
				}, func() (*http.Request, error) {
					req, err := http.NewRequestWithContext(gCtx, "GET", githubURL, nil)
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
					continue
				}
				if resp == nil {
					continue
				}

				if resp.StatusCode != http.StatusOK {
					slog.Warn("Worker: [WARN] GitHub API returned non-OK status", "status", resp.StatusCode, "cve_id", cveID)
					_ = resp.Body.Close()
					continue
				}

				err = json.NewDecoder(resp.Body).Decode(&ghResp)
				_ = resp.Body.Close()
				if err != nil {
					slog.Error("Worker: [ERROR] Failed to decode GitHub response", "cve_id", cveID, "error", err)
					continue
				}

				select {
				case updateChan <- githubUpdateItem{cveID: cveID, totalCount: ghResp.TotalCount}:
					atomic.AddInt64(&processedCount, 1)
				case <-gCtx.Done():
					return gCtx.Err()
				}
			}
			return nil
		})
	}

	// Distribute CVE IDs
DistributeLoop:
	for _, cveID := range cveIDs {
		select {
		case cveChan <- cveID:
		case <-gCtx.Done():
			break DistributeLoop
		}
	}
	close(cveChan)

	if err := g.Wait(); err != nil && err != context.Canceled {
		slog.Error("Worker: [ERROR] GitHub buzz sync workers failed", "error", err)
	}

	close(updateChan)
	<-collectorDone

	w.updateTaskStats(ctx, "github_buzz_sync")
	slog.Info("Worker: [SYNC] GitHub Social Buzz synchronization complete.", "duration", time.Since(start), "processed", atomic.LoadInt64(&processedCount))
}

func (w *Worker) updateGitHubBatch(ctx context.Context, updates []githubUpdateItem) {
	if len(updates) == 0 {
		return
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to begin transaction for GitHub updates", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	query := "UPDATE cves SET github_poc_count = $1 WHERE cve_id = $2"
	for _, up := range updates {
		if _, err := tx.Exec(ctx, query, up.totalCount, up.cveID); err != nil {
			slog.Error("Worker: [ERROR] Failed to update GitHub buzz in DB", "cve_id", up.cveID, "error", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: [ERROR] Failed to commit GitHub updates", "error", err)
	}
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
