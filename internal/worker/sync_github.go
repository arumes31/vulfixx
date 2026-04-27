package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"
)

func (w *Worker) syncGitHubBuzzPeriodically(ctx context.Context) {
	w.syncGitHubBuzz(ctx)
	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncGitHubBuzz(ctx)
		}
	}
}

func (w *Worker) syncGitHubBuzz(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting GitHub Social Buzz synchronization...")
	rows, err := w.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE published_date > NOW() - INTERVAL '14 days' ORDER BY published_date DESC")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for GitHub sync: %v", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			log.Printf("Worker: Error scanning CVE row for GitHub sync: %v", err)
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Worker: [ERROR] Row iteration error in syncGitHubBuzz: %v", err)
	}

	start := time.Now()
CVELoop:
	for _, cveID := range cveIDs {

		select {
		case <-ctx.Done():
			return
		default:
		}

		const maxGHRetries = 3
		var ghResp struct {
			TotalCount int `json:"total_count"`
		}
		for attempt := 0; attempt <= maxGHRetries; attempt++ {
			githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
			req, err := http.NewRequestWithContext(ctx, "GET", githubURL, nil)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to create GitHub request for %s: %v", cveID, err)
				continue CVELoop
			}
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "Vulfixx-Threat-Intel")
			resp, err := w.HTTP.Do(req)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to fetch GitHub buzz for %s: %v", cveID, err)
				continue CVELoop
			}
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
				_ = resp.Body.Close()
				var waitDur time.Duration
				if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
					if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
						waitDur = time.Until(time.Unix(ts, 0))
						if waitDur < 0 {
							waitDur = 0
						}
					}
				}
				if waitDur == 0 {
					waitDur = time.Duration(math.Pow(2, float64(attempt+1))) * time.Second
				}
				log.Printf("Worker: [WARN] GitHub rate limited for %s, waiting %v (attempt %d/%d)", cveID, waitDur, attempt+1, maxGHRetries)
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDur):
				}
				continue // retry
			}
			if resp.StatusCode != http.StatusOK {
				log.Printf("Worker: [WARN] GitHub API returned status %d for %s", resp.StatusCode, cveID)
				_ = resp.Body.Close()
				continue CVELoop
			}
			err = json.NewDecoder(resp.Body).Decode(&ghResp)
			_ = resp.Body.Close()
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to decode GitHub response for %s: %v", cveID, err)
				continue CVELoop
			}
			break // success
		}
		_, err := w.Pool.Exec(ctx, "UPDATE cves SET github_poc_count = $1 WHERE cve_id = $2", ghResp.TotalCount, cveID)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to update GitHub buzz for %s: %v", cveID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(7 * time.Second):
		}
	}
	log.Printf("Worker: [SYNC] GitHub Social Buzz synchronization complete. Duration: %v", time.Since(start))
}
