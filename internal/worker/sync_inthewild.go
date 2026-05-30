package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

func (w *Worker) syncInTheWildPeriodically(ctx context.Context) {
	// Initial wait and first run
	w.waitUntilNextRun(ctx, "inthewild_sync", 12*time.Hour, 4*time.Minute)
	w.syncInTheWild(ctx)

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncInTheWild(ctx)
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

	type itwUpdate struct {
		cveID string
		data  []byte
	}
	var updates []itwUpdate
	var mu sync.Mutex

	g, gCtx := errgroup.WithContext(ctx)
	cveChan := make(chan string)
	var processedCount int32

	// Use a worker pool to process CVEs concurrently while respecting rate limits.
	// We use a global rate limiter to ensure we don't exceed the API rate limit (approx 40 RPM).
	numWorkers := 5
	limiter := rate.NewLimiter(rate.Every(1500*time.Millisecond), 1)

	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			for cveID := range cveChan {
				if err := limiter.Wait(gCtx); err != nil {
					return err
				}

				data, err := w.fetchInTheWildData(gCtx, cveID)
				if err != nil {
					// Skip and continue
					continue
				}

				var dataJSON []byte
				if data != nil {
					dataJSON, err = json.Marshal(data)
					if err != nil {
						slog.Error("Worker: [ERROR] Failed to marshal InTheWild data", "cve_id", cveID, "error", err)
						continue
					}
				}

				mu.Lock()
				updates = append(updates, itwUpdate{cveID: cveID, data: dataJSON})
				mu.Unlock()
			}
			return nil
		})
	}

	// Feed the workers
	go func() {
		defer close(cveChan)
		for _, id := range cveIDs {
			select {
			case <-gCtx.Done():
				return
			case cveChan <- id:
			}
		}
	}()

	if err := g.Wait(); err != nil && err != context.Canceled && ctx.Err() == nil {
		slog.Error("Worker: [ERROR] InTheWild sync worker group error", "error", err)
	}

	if len(updates) == 0 {
		w.updateTaskStats(ctx, "inthewild_sync")
		return
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to begin transaction for InTheWild updates", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch := &pgx.Batch{}
	for _, up := range updates {
		if up.data != nil {
			batch.Queue(`
				UPDATE cves
				SET inthewild_data = $1, inthewild_last_updated = NOW()
				WHERE cve_id = $2
			`, up.data, up.cveID)
		} else {
			batch.Queue("UPDATE cves SET inthewild_last_updated = NOW() WHERE cve_id = $1", up.cveID)
		}
	}

	br := tx.SendBatch(ctx, batch)
	if br != nil {
		for _, up := range updates {
			if _, err := br.Exec(); err == nil {
				if up.data != nil {
					atomic.AddInt32(&processedCount, 1)
				}
			}
		}
		_ = br.Close()
	} else {
		// Fallback for mocks/drivers that don't support batching
		for _, up := range updates {
			var err error
			if up.data != nil {
				_, err = tx.Exec(ctx, `
					UPDATE cves
					SET inthewild_data = $1, inthewild_last_updated = NOW()
					WHERE cve_id = $2
				`, up.data, up.cveID)
			} else {
				_, err = tx.Exec(ctx, "UPDATE cves SET inthewild_last_updated = NOW() WHERE cve_id = $1", up.cveID)
			}
			if err == nil && up.data != nil {
				atomic.AddInt32(&processedCount, 1)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: [ERROR] Failed to commit InTheWild updates", "error", err)
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

	resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
		MaxRetries:  3,
		MaxWait:     2 * time.Minute,
		ShouldRetry: DefaultShouldRetry,
		Label:       "InTheWild API",
	}, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel/2.0")
		return req, nil
	})

	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("InTheWild API returned nil response")
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

	return result, nil
}
