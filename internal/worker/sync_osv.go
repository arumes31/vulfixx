package worker

import (
	"bytes"
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

	// Fetch recent CVEs to update OSV data
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE published_date > NOW() - INTERVAL '30 days'
		ORDER BY published_date DESC LIMIT 50
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
			_, err = w.Pool.Exec(ctx, "UPDATE cves SET osv_data = $1 WHERE cve_id = $2", dataJSON, cveID)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to update OSV data for %s: %v", cveID, err)
			}
			count++
		}

		// OSV API is very generous but we still throttle
		time.Sleep(500 * time.Millisecond)
	}
	
	w.updateTaskStats(ctx, "osv_sync")
	log.Printf("Worker: [SYNC] OSV synchronization complete. Updated %d records.", count)
}

func (w *Worker) fetchOSVData(ctx context.Context, cveID string) (map[string]interface{}, error) {
	query := map[string]string{"cve_id": cveID}
	body, _ := json.Marshal(query)
	
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel/2.0")

	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var result struct {
		Vulns []map[string]interface{} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Vulns) > 0 {
		return result.Vulns[0], nil
	}

	return nil, nil
}
