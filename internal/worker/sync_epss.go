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

func syncEPSSPeriodically(ctx context.Context) {
	syncEPSS(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncEPSS(ctx)
		}
	}
}

func syncEPSS(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting EPSS score synchronization...")
	rows, err := db.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE published_date > NOW() - INTERVAL '30 days'")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for EPSS sync: %v", err)
		return
	}
	
	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			log.Printf("Worker: Error scanning CVE ID: %v", err)
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Worker: [ERROR] Row iteration error in syncEPSS: %v", err)
	}
	rows.Close()

	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	for _, cveID := range cveIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		epssURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID)
		req, err := http.NewRequestWithContext(ctx, "GET", epssURL, nil)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to create EPSS request for %s: %v", cveID, err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to fetch EPSS for %s: %v", cveID, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Worker: [WARN] EPSS API returned status %d for %s", resp.StatusCode, cveID)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				time.Sleep(5 * time.Second)
			}
			continue
		}
		var epssResp struct {
			Data []struct {
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		err = json.NewDecoder(resp.Body).Decode(&epssResp)
		_ = resp.Body.Close()
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to decode EPSS for %s: %v", cveID, err)
			continue
		}
		if len(epssResp.Data) > 0 {
			score := 0.0
			if _, err := fmt.Sscanf(epssResp.Data[0].EPSS, "%f", &score); err != nil {
				log.Printf("EPSS: Failed to parse score for %s: %v", cveID, err)
				continue
			}
			_, err = db.Pool.Exec(ctx, "UPDATE cves SET epss_score = $1 WHERE cve_id = $2", score, cveID)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to update EPSS for %s: %v", cveID, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	log.Printf("Worker: [SYNC] EPSS score synchronization complete. Duration: %v", time.Since(start))
}
