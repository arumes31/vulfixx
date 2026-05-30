package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"cve-tracker/internal/models"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

// fetchOSINTLinks collects links and mention counts from external platforms (HN, Reddit) for a given CVE.
func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) models.JSONBMap {
	cacheKey := fmt.Sprintf("osint_links:%s", cveID)

	// Try to get from cache first
	if val, err := w.Redis.Get(ctx, cacheKey).Result(); err == nil {
		var cachedData models.JSONBMap
		if err := json.Unmarshal([]byte(val), &cachedData); err == nil {
			return cachedData
		}
	} else if err != redis.Nil {
		slog.Warn("Worker: Failed to get OSINT cache", "cve_id", cveID, "error", err)
	}

	data := make(models.JSONBMap)
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)

	// Hacker News
	g.Go(func() error {
		if count, links, err := w.fetchHNMentions(gctx, cveID); err == nil {
			mu.Lock()
			data["hn"] = links
			data["hn_mentions"] = count
			mu.Unlock()
		} else {
			slog.Error("Worker: Failed to fetch HN results", "cve_id", cveID, "error", err)
		}
		return nil
	})

	// Reddit
	g.Go(func() error {
		if count, links, err := w.fetchRedditMentions(gctx, cveID); err == nil {
			mu.Lock()
			data["reddit"] = links
			data["reddit_mentions"] = count
			mu.Unlock()
		} else {
			slog.Error("Worker: Failed to fetch Reddit results", "cve_id", cveID, "error", err)
		}
		return nil
	})

	_ = g.Wait()

	// Cache the result for 6 hours
	if encoded, err := json.Marshal(data); err == nil {
		if err := w.Redis.Set(ctx, cacheKey, encoded, 6*time.Hour).Err(); err != nil {
			slog.Warn("Worker: Failed to set OSINT cache", "cve_id", cveID, "error", err)
		}
	}

	return data
}

func (w *Worker) fetchHNMentions(ctx context.Context, cveID string) (int, []map[string]string, error) {
	if w.HNClient == nil {
		return 0, nil, fmt.Errorf("HNClient not initialized")
	}
	w.initLimiters()
	if err := w.HNLimiter.Wait(ctx); err != nil {
		return 0, nil, err
	}
	return w.HNClient.FetchMentions(ctx, cveID)
}

func (w *Worker) fetchRedditMentions(ctx context.Context, cveID string) (int, []map[string]string, error) {
	if !isValidCVEID(cveID) {
		return 0, nil, fmt.Errorf("invalid CVE ID: %s", cveID)
	}

	w.initLimiters()
	if err := w.RedditLimiter.Wait(ctx); err != nil {
		return 0, nil, err
	}
	encodedID := url.QueryEscape(cveID)
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=new&limit=10", encodedID)

	resp, err := DoWithRetry(ctx, w.HTTP, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
		Label:       "Reddit Mention Fetch",
	}, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", redditURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Vulfixx/2.0 (Threat Intelligence Bot)")
		return req, nil
	})
	if err != nil {
		return 0, nil, err
	}

	if resp == nil {
		return 0, nil, fmt.Errorf("Reddit API returned nil response")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("Reddit API returned status %d", resp.StatusCode)
	}

	var rResp struct {
		Data struct {
			Children []struct {
				Data struct {
					Title     string `json:"title"`
					Permalink string `json:"permalink"`
				} `json:"data"`
			} `json:"children"`
		} `json:"data"`
	}

	// Limit response size to 1MB to prevent DoS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&rResp); err != nil {
		return 0, nil, err
	}

	links := []map[string]string{}
	for _, child := range rResp.Data.Children {
		if !isValidRedditPermalink(child.Data.Permalink) {
			continue
		}
		redditLink := fmt.Sprintf("https://www.reddit.com%s", child.Data.Permalink)
		links = append(links, map[string]string{"title": child.Data.Title, "url": redditLink})
	}

	return len(links), links, nil
}
