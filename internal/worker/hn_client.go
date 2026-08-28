package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	resp, err := DoWithRetry(ctx, c.httpClient, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
		Label:       "HN Mention Fetch",
	}, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", hnURL, nil)
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
		return 0, nil, fmt.Errorf("HN API returned nil response") //nolint:staticcheck // HN is a proper name.
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("Hacker News API returned status %d", resp.StatusCode) //nolint:staticcheck // Hacker News is a proper name.
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
