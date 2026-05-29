package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// fetchOSINTLinks collects links from external platforms (HN, Reddit) for a given CVE.
func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) map[string]interface{} {
	cacheKey := fmt.Sprintf("osint_links:%s", cveID)

	// Try to get from cache first
	if val, err := w.Redis.Get(ctx, cacheKey).Result(); err == nil {
		var cachedData map[string]interface{}
		if err := json.Unmarshal([]byte(val), &cachedData); err == nil {
			return cachedData
		}
	} else if err != redis.Nil {
		slog.Warn("Worker: Failed to get OSINT cache", "cve_id", cveID, "error", err)
	}

	data := make(map[string]interface{})

	// Hacker News
	if _, links, err := w.fetchHNMentions(ctx, cveID); err == nil {
		data["hn"] = links
	} else {
		slog.Error("Worker: Failed to fetch HN results", "cve_id", cveID, "error", err)
	}

	// Reddit
	if _, links, err := w.fetchRedditMentions(ctx, cveID); err == nil {
		data["reddit"] = links
	} else {
		slog.Error("Worker: Failed to fetch Reddit results", "cve_id", cveID, "error", err)
	}

	// Cache the result for 6 hours
	if encoded, err := json.Marshal(data); err == nil {
		if err := w.Redis.Set(ctx, cacheKey, encoded, 6*time.Hour).Err(); err != nil {
			slog.Warn("Worker: Failed to set OSINT cache", "cve_id", cveID, "error", err)
		}
	}

	return data
}
