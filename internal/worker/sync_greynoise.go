package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

func (w *Worker) syncGreyNoisePeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "greynoise_sync", 6*time.Hour, 2*time.Minute)
	w.runWithLock(ctx, "greynoise_sync", 30*time.Minute, w.syncGreyNoise)

	ticker := w.TickerFactory(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "greynoise_sync", 30*time.Minute, w.syncGreyNoise)
		}
	}
}

func (w *Worker) syncGreyNoise(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting GreyNoise Intelligence synchronization...")
	// Prioritize CVEs that haven't been checked yet, then oldest ones (older than 30 days)
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE greynoise_last_updated IS NULL OR greynoise_last_updated < NOW() - INTERVAL '30 days'
		ORDER BY greynoise_last_updated ASC NULLS FIRST
		LIMIT 200
	`)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch CVEs for GreyNoise sync", "error", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			cveIDs = append(cveIDs, id)
		}
	}

	if len(cveIDs) == 0 {
		slog.Info("Worker: [SYNC] No CVEs to sync with GreyNoise.")
		return
	}

	var processedCount int64
	// Respect Community API rate limits (~60 rpm -> 1 req/sec)
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	g, gCtx := errgroup.WithContext(ctx)
	cveChan := make(chan string)

	// Start concurrent workers
	numWorkers := 5
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			for cveID := range cveChan {
				if err := limiter.Wait(gCtx); err != nil {
					return err
				}

				hits, err := w.fetchGreyNoiseHits(gCtx, cveID)
				if err != nil {
					// Don't fail the whole group for one API error, but log it
					slog.Debug("Worker: [DEBUG] Failed to fetch GreyNoise hits", "cve_id", cveID, "error", err)
					continue
				}

				_, err = w.Pool.Exec(gCtx, `
					UPDATE cves
					SET greynoise_hits = $1, greynoise_last_updated = NOW()
					WHERE cve_id = $2
				`, hits, cveID)
				if err != nil {
					slog.Error("Worker: [ERROR] Failed to update GreyNoise hits", "cve_id", cveID, "error", err)
				} else {
					atomic.AddInt64(&processedCount, 1)
				}
			}
			return nil
		})
	}

	// Distribute CVE IDs to workers
Loop:
	for _, cveID := range cveIDs {
		select {
		case cveChan <- cveID:
		case <-gCtx.Done():
			break Loop
		}
	}
	close(cveChan)

	if err := g.Wait(); err != nil && err != context.Canceled {
		slog.Error("Worker: [ERROR] GreyNoise sync workers failed", "error", err)
	}

	w.updateTaskStats(ctx, "greynoise_sync")
	slog.Info("Worker: [SYNC] GreyNoise synchronization complete.", "processed_count", atomic.LoadInt64(&processedCount))
}

func (w *Worker) fetchGreyNoiseHits(ctx context.Context, cveID string) (int, error) {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/cve/%s", cveID)
	resp, err := w.doRequest(ctx, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
		Label:       "GreyNoise Fetch",
	}, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GreyNoise API returned status %d", resp.StatusCode)
	}

	var data struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, err
	}

	return data.Total, nil
}
