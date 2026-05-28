package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// HNClient defines the interface for fetching Hacker News mentions.
type HNClient interface {
	FetchMentions(ctx context.Context, query string) (int, []map[string]string, error)
}

// algoliaHNClient implements HNClient using the Algolia API.
type algoliaHNClient struct {
	httpClient HTTPClient
}

// NewHNClient creates a new HNClient implementation using Algolia.
func NewHNClient(httpClient HTTPClient) HNClient {
	return &algoliaHNClient{
		httpClient: httpClient,
	}
}

// FetchMentions searches Hacker News for stories matching the query.
func (c *algoliaHNClient) FetchMentions(ctx context.Context, query string) (int, []map[string]string, error) {
	if !isValidCVEID(query) {
		return 0, nil, fmt.Errorf("invalid CVE ID for HN search: %s", query)
	}

	encodedQuery := url.QueryEscape(query)
	hnURL := fmt.Sprintf("https://hn.algolia.com/api/v1/search?query=%s&tags=story", encodedQuery)

	var resp *http.Response
	var err error
	for retries := 0; retries < 3; retries++ {
		req, errReq := http.NewRequestWithContext(ctx, "GET", hnURL, nil)
		if errReq != nil {
			return 0, nil, errReq
		}
		req.Header.Set("User-Agent", "Vulfixx/2.0 (Threat Intelligence Bot)")

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return 0, nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			waitTime := 5 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, errSec := strconv.Atoi(ra); errSec == nil {
					waitTime = time.Duration(seconds) * time.Second
				}
			}
			slog.Warn("Worker: HN rate limited", "query", query, "retry_after", waitTime)
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(waitTime):
				continue
			}
		}
		break
	}

	if resp == nil {
		return 0, nil, fmt.Errorf("HN API returned nil response")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("Hacker News API returned status %d", resp.StatusCode)
	}

	var hnResp struct {
		NbHits int `json:"nbHits"`
		Hits   []struct {
			Title    string `json:"title"`
			ObjectID string `json:"objectID"`
		} `json:"hits"`
	}

	// Limit response size to 1MB to prevent DoS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&hnResp); err != nil {
		return 0, nil, err
	}

	links := []map[string]string{}
	for _, hit := range hnResp.Hits {
		if !isNumeric(hit.ObjectID) {
			continue
		}
		hnLink := fmt.Sprintf("https://news.ycombinator.com/item?id=%s", hit.ObjectID)
		links = append(links, map[string]string{"title": hit.Title, "url": hnLink})
	}

	return hnResp.NbHits, links, nil
}
