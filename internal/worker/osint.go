package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"cve-tracker/internal/models"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

// fetchOSINTLinks collects links from external platforms (HN, Reddit) for a given CVE.
func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) models.JSONBMap {
	cacheKey := fmt.Sprintf("osint_links:%s", cveID)

	// Try to get from cache first
	if w.Redis != nil {
		if val, err := w.Redis.Get(ctx, cacheKey).Result(); err == nil {
			var cachedData models.JSONBMap
			if err := json.Unmarshal([]byte(val), &cachedData); err == nil {
				return cachedData
			}
		} else if err != redis.Nil {
			slog.Warn("Worker: Failed to get OSINT cache", "cve_id", cveID, "error", err)
		}
	}

	data := make(models.JSONBMap)
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)

	// HN
	g.Go(func() error {
		if _, links, err := w.fetchHNMentions(gctx, cveID); err == nil {
			mu.Lock()
			data["hn"] = links
			mu.Unlock()
		} else {
			slog.Error("Worker: Failed to fetch HN results", "cve_id", cveID, "error", err)
		}
		return nil
	})

	// Reddit
	g.Go(func() error {
		if _, links, err := w.fetchRedditMentions(gctx, cveID); err == nil {
			mu.Lock()
			data["reddit"] = links
			mu.Unlock()
		} else {
			slog.Error("Worker: Failed to fetch Reddit results", "cve_id", cveID, "error", err)
		}
		return nil
	})

	_ = g.Wait()

	// Cache the result for 6 hours
	if w.Redis != nil {
		if encoded, err := json.Marshal(data); err == nil {
			if err := w.Redis.Set(ctx, cacheKey, encoded, 6*time.Hour).Err(); err != nil {
				slog.Warn("Worker: Failed to set OSINT cache", "cve_id", cveID, "error", err)
			}
		}
	}

	return data
}
