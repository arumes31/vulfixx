package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func fetchOSINTLinks(ctx context.Context, cveID string) map[string]interface{} {
	data := make(map[string]interface{})
	client := &http.Client{Timeout: 5 * time.Second}

	// Hacker News
	hnURL := fmt.Sprintf("https://hn.algolia.com/api/v1/search?query=%s&tags=story", cveID)
	req, _ := http.NewRequestWithContext(ctx, "GET", hnURL, nil)
	if resp, err := client.Do(req); err == nil {
		var hnResp struct {
			Hits []struct {
				Title string `json:"title"`
				URL   string `json:"url"`
				ObjectID string `json:"objectID"`
			} `json:"hits"`
		}
		if json.NewDecoder(resp.Body).Decode(&hnResp) == nil {
			links := []map[string]string{}
			for _, hit := range hnResp.Hits {
				hnLink := fmt.Sprintf("https://news.ycombinator.com/item?id=%s", hit.ObjectID)
				links = append(links, map[string]string{"title": hit.Title, "url": hnLink})
			}
			data["hn"] = links
		}
		resp.Body.Close()
	}

	// Reddit
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=relevance&t=all", cveID)
	req, _ = http.NewRequestWithContext(ctx, "GET", redditURL, nil)
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel-Bot/1.0")
	if resp, err := client.Do(req); err == nil {
		var rResp struct {
			Data struct {
				Children []struct {
					Data struct {
						Title string `json:"title"`
						Permalink string `json:"permalink"`
					} `json:"data"`
				} `json:"children"`
			} `json:"data"`
		}
		if json.NewDecoder(resp.Body).Decode(&rResp) == nil {
			links := []map[string]string{}
			for _, child := range rResp.Data.Children {
				redditLink := fmt.Sprintf("https://www.reddit.com%s", child.Data.Permalink)
				links = append(links, map[string]string{"title": child.Data.Title, "url": redditLink})
			}
			data["reddit"] = links
		}
		resp.Body.Close()
	}

	return data
}

func classifyVendorAdvisories(references []string) []string {
	advisories := []string{}
	keywords := []string{
		"advisory", "bulletin", "security-advisories", "msrc", "security/notices",
		"security/advisories", "kb", "security-center", "ghsa", "osv",
	}
	
	for _, ref := range references {
		lower := strings.ToLower(ref)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				advisories = append(advisories, ref)
				break
			}
		}
	}
	return advisories
}
