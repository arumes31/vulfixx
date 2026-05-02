package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (w *Worker) syncOSVPeriodically(ctx context.Context) {
	// Initial delay
	time.Sleep(3 * time.Minute)
	w.syncOSV(ctx)

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncOSV(ctx)
		}
	}
}

func (w *Worker) syncOSV(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting OSV (Open Source Vulnerabilities) synchronization...")

	// Prioritize CVEs that haven't been checked yet, focusing on newest and most critical
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE osv_last_updated IS NULL
		ORDER BY published_date DESC NULLS LAST, cvss_score DESC NULLS LAST
		LIMIT 100
	`)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for OSV sync: %v", err)
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

		osvData, err := w.fetchOSVData(ctx, cveID)
		if err != nil {
			continue
		}

		if osvData != nil {
			dataJSON, _ := json.Marshal(osvData)
			_, err = w.Pool.Exec(ctx, "UPDATE cves SET osv_data = $1, osv_last_updated = NOW() WHERE cve_id = $2", dataJSON, cveID)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to update OSV data for %s: %v", cveID, err)
			}
			count++
		} else {
			// Mark as checked even if no data found to avoid re-checking in the next run
			_, _ = w.Pool.Exec(ctx, "UPDATE cves SET osv_last_updated = NOW() WHERE cve_id = $1", cveID)
		}

		// OSV API is very generous but we still throttle
		time.Sleep(500 * time.Millisecond)
	}
	
	w.updateTaskStats(ctx, "osv_sync")
	log.Printf("Worker: [SYNC] OSV synchronization complete. Updated %d records.", count)
}

func (w *Worker) fetchOSVData(ctx context.Context, cveID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel/2.0")

	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
