package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type HNHit struct {
	Title    string `json:"title"`
	URL      string `json:"url"`
	ObjectID string `json:"objectID"`
}

type HNResponse struct {
	Hits   []HNHit `json:"hits"`
	NbHits int     `json:"nbHits"`
}

func (w *Worker) searchHackerNews(ctx context.Context, query string) (*HNResponse, error) {
	u, err := url.Parse("https://hn.algolia.com/api/v1/search")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("query", query)
	q.Set("tags", "story")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel-Bot/1.0")

	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HN API returned status %d", resp.StatusCode)
	}

	var hnResp HNResponse
	if err := json.NewDecoder(resp.Body).Decode(&hnResp); err != nil {
		return nil, err
	}

	return &hnResp, nil
}

func (w *Worker) fetchOSINTLinks(ctx context.Context, cveID string) map[string]interface{} {
	var req *http.Request
	var err error
	data := make(map[string]interface{})
	encodedID := url.QueryEscape(cveID)

	// Hacker News
	if hnResp, err := w.searchHackerNews(ctx, cveID); err != nil {
		log.Printf("Failed to fetch HN results for %s: %v", cveID, err)
	} else {
		links := []map[string]string{}
		for _, hit := range hnResp.Hits {
			hnLink := fmt.Sprintf("https://news.ycombinator.com/item?id=%s", hit.ObjectID)
			links = append(links, map[string]string{"title": hit.Title, "url": hnLink})
		}
		data["hn"] = links
	}

	// Reddit
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=relevance&t=all", encodedID)

	var resp *http.Response
	for retries := 0; retries < 3; retries++ {
		req, err = http.NewRequestWithContext(ctx, "GET", redditURL, nil)
		if err != nil {
			log.Printf("Failed to create Reddit request (retry %d): %v", retries, err)
			break
		}
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel-Bot/1.0")

		resp, err = w.HTTP.Do(req)
		if err != nil {
			log.Printf("Failed to fetch Reddit results for %s: %v", cveID, err)
			break
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			waitTime := 5 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, err := strconv.Atoi(ra); err == nil {
					waitTime = time.Duration(seconds) * time.Second
				}
			}
			resp = nil
			log.Printf("Reddit rate limited, waiting %v...", waitTime)
			if retries == 2 {
				break
			}
			select {
			case <-ctx.Done():
				return data
			case <-time.After(waitTime):
				continue
			}
		}
		break
	}
	if err == nil && resp != nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
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
			if err := json.NewDecoder(resp.Body).Decode(&rResp); err == nil {
				links := []map[string]string{}
				for _, child := range rResp.Data.Children {
					redditLink := fmt.Sprintf("https://www.reddit.com%s", child.Data.Permalink)
					links = append(links, map[string]string{"title": child.Data.Title, "url": redditLink})
				}
				data["reddit"] = links
			} else {
				log.Printf("Failed to decode Reddit response for %s: %v", cveID, err)
			}
		} else if resp.StatusCode != http.StatusNotFound {
			log.Printf("Reddit API returned status %d for %s", resp.StatusCode, cveID)
		}
	}

	return data
}
