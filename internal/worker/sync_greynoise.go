package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (w *Worker) syncGreyNoisePeriodically(ctx context.Context) {
	// Initial delay to avoid race conditions with NVD sync on startup
	time.Sleep(2 * time.Minute)
	w.syncGreyNoise(ctx)

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncGreyNoise(ctx)
		}
	}
}

func (w *Worker) syncGreyNoise(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting GreyNoise Intelligence synchronization...")
	
	// Prioritize CVEs that haven't been checked yet, focusing on newest and most critical
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE greynoise_last_updated IS NULL
		ORDER BY published_date DESC NULLS LAST, cvss_score DESC NULLS LAST
		LIMIT 100
	`)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for GreyNoise sync: %v", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			cveIDs = append(cveIDs, id)
		}
	}

	count := 0
	for _, cveID := range cveIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		hits, err := w.fetchGreyNoiseHits(ctx, cveID)
		if err != nil {
			// Don't log normal "not found" as error, but log API issues
			continue
		}

		_, err = w.Pool.Exec(ctx, `
			UPDATE cves 
			SET greynoise_hits = $1, greynoise_last_updated = NOW() 
			WHERE cve_id = $2
		`, hits, cveID)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to update GreyNoise hits for %s: %v", cveID, err)
		}
		count++

		// Respect Community API rate limits
		time.Sleep(1500 * time.Millisecond)
	}
	
	w.updateTaskStats(ctx, "greynoise_sync")
	log.Printf("Worker: [SYNC] GreyNoise synchronization complete. Processed %d CVEs.", count)
}

func (w *Worker) fetchGreyNoiseHits(ctx context.Context, cveID string) (int, error) {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/cve/%s", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel/2.0")

	resp, err := w.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GreyNoise API returned status %d", resp.StatusCode)
	}

	var data struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, err
	}

	return data.Total, nil
}
