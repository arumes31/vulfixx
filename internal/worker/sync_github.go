package worker

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func syncGitHubBuzzPeriodically(ctx context.Context) {
	syncGitHubBuzz(ctx)
	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncGitHubBuzz(ctx)
		}
	}
}

func syncGitHubBuzz(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting GitHub Social Buzz synchronization...")
	rows, err := db.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE published_date > NOW() - INTERVAL '14 days' ORDER BY published_date DESC")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for GitHub sync: %v", err)
		return
	}
	defer rows.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			log.Printf("Worker: Error scanning CVE row for GitHub sync: %v", err)
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
		req, _ := http.NewRequestWithContext(ctx, "GET", githubURL, nil)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to fetch GitHub buzz for %s: %v", cveID, err)
			continue
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			log.Printf("Worker: [WARN] GitHub API rate limited (status %d), pausing sync for %s", resp.StatusCode, cveID)
			break
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Worker: [WARN] GitHub API returned status %d for %s", resp.StatusCode, cveID)
			_ = resp.Body.Close()
			continue
		}
		var ghResp struct {
			TotalCount int `json:"total_count"`
		}
		err = json.NewDecoder(resp.Body).Decode(&ghResp)
		_ = resp.Body.Close()
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to decode GitHub response for %s: %v", cveID, err)
			continue
		}
		_, err = db.Pool.Exec(ctx, "UPDATE cves SET github_poc_count = $1 WHERE cve_id = $2", ghResp.TotalCount, cveID)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to update GitHub buzz for %s: %v", cveID, err)
		}
		time.Sleep(7 * time.Second)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Worker: [ERROR] Row iteration error in syncGitHubBuzz: %v", err)
	}
	log.Println("Worker: [SYNC] GitHub Social Buzz synchronization complete.")
}
