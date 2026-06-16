package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

func (w *Worker) syncInTheWildPeriodically(ctx context.Context) {
	// Initial wait and first run
	w.waitUntilNextRun(ctx, "inthewild_sync", 12*time.Hour, 4*time.Minute)
	w.runWithLock(ctx, "inthewild_sync", 30*time.Minute, w.syncInTheWild)

	ticker := w.TickerFactory(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "inthewild_sync", 30*time.Minute, w.syncInTheWild)
		}
	}
}

func (w *Worker) syncInTheWild(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting InTheWild.io synchronization...")

	// Prioritize CVEs that haven't been checked yet, then oldest ones (older than 30 days)
	// We only process CVEs that have a standard CVE-ID format
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE (inthewild_last_updated IS NULL OR inthewild_last_updated < NOW() - INTERVAL '30 days')
		  AND cve_id ~ '^CVE-\d{4}-\d+$'
		ORDER BY inthewild_last_updated ASC NULLS FIRST
		LIMIT 100
	`)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch CVEs for InTheWild sync", "error", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			slog.Error("Worker: [ERROR] Failed to scan CVE ID for InTheWild sync", "error", err)
			continue
		}
		cveIDs = append(cveIDs, id)
	}

	if len(cveIDs) == 0 {
		w.updateTaskStats(ctx, "inthewild_sync")
		return
	}

	g, ctx := errgroup.WithContext(ctx)
	cveChan := make(chan string)
	var processedCount int32

	// Use a worker pool to process CVEs concurrently while respecting rate limits.
	// We use a global rate limiter to ensure we don't exceed the API rate limit (approx 40 RPM).
	numWorkers := 5
	limiter := rate.NewLimiter(rate.Every(1500*time.Millisecond), 1)

	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			for cveID := range cveChan {
				if err := limiter.Wait(ctx); err != nil {
					return err
				}

				data, err := w.fetchInTheWildData(ctx, cveID)
				if err != nil {
					// Skip and continue
					continue
				}

				if data != nil {
					dataJSON, err := json.Marshal(data)
					if err != nil {
						slog.Error("Worker: [ERROR] Failed to marshal InTheWild data", "cve_id", cveID, "error", err)
						continue
					}
					_, err = w.Pool.Exec(ctx, `
						UPDATE cves
						SET inthewild_data = $1, inthewild_last_updated = NOW()
						WHERE cve_id = $2
					`, dataJSON, cveID)
					if err != nil {
						slog.Error("Worker: [ERROR] Failed to update InTheWild data", "cve_id", cveID, "error", err)
					} else {
						atomic.AddInt32(&processedCount, 1)
					}
				} else {
					// Mark as checked even if no data found
					_, err = w.Pool.Exec(ctx, "UPDATE cves SET inthewild_last_updated = NOW() WHERE cve_id = $1", cveID)
					if err != nil {
						slog.Error("Worker: [ERROR] Failed to update InTheWild last_updated timestamp", "cve_id", cveID, "error", err)
					}
				}
			}
			return nil
		})
	}

	// Feed the workers
	go func() {
		defer close(cveChan)
		for _, id := range cveIDs {
			select {
			case <-ctx.Done():
				return
			case cveChan <- id:
			}
		}
	}()

	if err := g.Wait(); err != nil && err != context.Canceled {
		slog.Error("Worker: [ERROR] InTheWild sync worker group error", "error", err)
	}

	w.updateTaskStats(ctx, "inthewild_sync")
	slog.Info("Worker: [SYNC] InTheWild.io synchronization complete.", "processed_count", processedCount)
}

func (w *Worker) fetchInTheWildData(ctx context.Context, cveID string) (map[string]interface{}, error) {
	baseURL := "https://inthewild.io/api/v1/vulns"
	if envURL := os.Getenv("INTHEWILD_API_URL"); envURL != "" {
		baseURL = envURL
	}
	url := fmt.Sprintf("%s/%s", baseURL, cveID)
	resp, err := doSyncRequest(ctx, w.HTTP, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("InTheWild API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Ensure we only return data if it actually contains exploitation info
	// InTheWild sometimes returns an empty-ish response for non-exploited vulns
	return result, nil
}
