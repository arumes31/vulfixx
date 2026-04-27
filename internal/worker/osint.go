package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func fetchOSINTLinks(ctx context.Context, cveID string) map[string]interface{} {
	data := make(map[string]interface{})
	client := &http.Client{Timeout: 5 * time.Second}

	// Hacker News
	hnURL := fmt.Sprintf("https://hn.algolia.com/api/v1/search?query=%s&tags=story", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", hnURL, nil)
	if err != nil {
		log.Printf("Failed to create HN request: %v", err)
	} else if resp, err := client.Do(req); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var hnResp struct {
				Hits []struct {
					Title    string `json:"title"`
					URL      string `json:"url"`
					ObjectID string `json:"objectID"`
				} `json:"hits"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&hnResp); err == nil {
				links := []map[string]string{}
				for _, hit := range hnResp.Hits {
					hnLink := fmt.Sprintf("https://news.ycombinator.com/item?id=%s", hit.ObjectID)
					links = append(links, map[string]string{"title": hit.Title, "url": hnLink})
				}
				data["hn"] = links
			} else {
				log.Printf("Failed to decode HN response for %s: %v", cveID, err)
			}
		} else {
			log.Printf("HN API returned status %d for %s", resp.StatusCode, cveID)
		}
	}

	// Reddit
	redditURL := fmt.Sprintf("https://www.reddit.com/search.json?q=%s&sort=relevance&t=all", cveID)
	req, err = http.NewRequestWithContext(ctx, "GET", redditURL, nil)
	if err != nil {
		log.Printf("Failed to create Reddit request: %v", err)
	} else {
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel-Bot/1.0")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
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
