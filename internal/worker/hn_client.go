package worker

import (
	"context"
	"encoding/json"
	"fmt"
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
	encodedQuery := url.QueryEscape(query)
	hnURL := fmt.Sprintf("https://hn.algolia.com/api/v1/search?query=%s&tags=story", encodedQuery)

	req, err := http.NewRequestWithContext(ctx, "GET", hnURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "Vulfixx/2.0 (Threat Intelligence Bot)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
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

	if err := json.NewDecoder(resp.Body).Decode(&hnResp); err != nil {
		return 0, nil, err
	}

	links := []map[string]string{}
	for _, hit := range hnResp.Hits {
		hnLink := fmt.Sprintf("https://news.ycombinator.com/item?id=%s", hit.ObjectID)
		links = append(links, map[string]string{"title": hit.Title, "url": hnLink})
	}

	return hnResp.NbHits, links, nil
}
