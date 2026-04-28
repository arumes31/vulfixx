package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (w *Worker) syncEPSSPeriodically(ctx context.Context) {
	w.syncEPSS(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncEPSS(ctx)
		}
	}
}

var defaultEPSSBaseURL = "https://api.first.org/data/v1/epss"

func (w *Worker) syncEPSS(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting EPSS score synchronization...")
	rows, err := w.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE published_date > NOW() - INTERVAL '30 days'")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for EPSS sync: %v", err)
		return
	}
	defer rows.Close()

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

	start := time.Now()
	for _, cveID := range cveIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		epssURL := fmt.Sprintf("%s?cve=%s", defaultEPSSBaseURL, cveID)
		var resp *http.Response
		var err error
		for retries := 0; retries < 3; retries++ {
			var req *http.Request
			req, err = http.NewRequestWithContext(ctx, "GET", epssURL, nil)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to create EPSS request for %s (retry %d): %v", cveID, retries, err)
				break
			}
			resp, err = w.HTTP.Do(req)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to fetch EPSS for %s: %v", cveID, err)
				break
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				_ = resp.Body.Close()
				resp = nil
				waitTime := 5 * time.Second
				log.Printf("EPSS rate limited, waiting %v...", waitTime)
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitTime):
					continue
				}
			}
			break
		}
		if err != nil || resp == nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("Worker: [WARN] EPSS API returned status %d for %s", resp.StatusCode, cveID)
			_ = resp.Body.Close()
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
			_, err = w.Pool.Exec(ctx, "UPDATE cves SET epss_score = $1 WHERE cve_id = $2", score, cveID)
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
