package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"cve-tracker/internal/models"

	"github.com/microcosm-cc/bluemonday"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

// fetchOSINTLinks collects links from external platforms (HN, Reddit) for a given CVE.
func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) models.JSONBMap {
	cacheKey := fmt.Sprintf("osint_links:%s", cveID)

	// Try to get from cache first if Redis is available
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
	strict := bluemonday.StrictPolicy()

	// Hacker News
	g.Go(func() error {
		count, links, err := w.fetchHNMentions(gctx, cveID)
		if err != nil {
			return fmt.Errorf("HN fetch error: %w", err)
		}

		for i := range links {
			links[i]["title"] = strict.Sanitize(links[i]["title"])
		}

		mu.Lock()
		data["hn"] = links
		data["hn_mentions"] = count
		mu.Unlock()
		return nil
	})

	// Reddit
	g.Go(func() error {
		count, links, err := w.fetchRedditMentions(gctx, cveID)
		if err != nil {
			return fmt.Errorf("Reddit fetch error: %w", err)
		}

		for i := range links {
			links[i]["title"] = strict.Sanitize(links[i]["title"])
		}

		mu.Lock()
		data["reddit"] = links
		data["reddit_mentions"] = count
		mu.Unlock()
		return nil
	})

	if err := g.Wait(); err != nil {
		slog.Error("Worker: OSINT fetching encountered partial or full errors", "cve_id", cveID, "error", err)
	}

	// Cache the result for 6 hours if Redis is available
	if w.Redis != nil {
		if encoded, err := json.Marshal(data); err == nil {
			if err := w.Redis.Set(ctx, cacheKey, encoded, 6*time.Hour).Err(); err != nil {
				slog.Warn("Worker: Failed to set OSINT cache", "cve_id", cveID, "error", err)
			}
		}
	}

	return data
}
