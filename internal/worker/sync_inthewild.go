package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func (w *Worker) syncInTheWildPeriodically(ctx context.Context) {
	// Initial wait and first run
	w.waitUntilNextRun(ctx, "inthewild_sync", 12*time.Hour, 4*time.Minute)
	w.syncInTheWild(ctx)

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncInTheWild(ctx)
		}
	}
}

func (w *Worker) syncInTheWild(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting InTheWild.io synchronization...")

	// Prioritize CVEs that haven't been checked yet, then oldest ones (older than 30 days)
	// We only process CVEs that have a standard CVE-ID format
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE (inthewild_last_updated IS NULL OR inthewild_last_updated < NOW() - INTERVAL '30 days')
		  AND cve_id ~ '^CVE-\d{4}-\d+$'
		ORDER BY inthewild_last_updated ASC NULLS FIRST
		LIMIT 100
	`)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for InTheWild sync: %v", err)
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

		data, err := w.fetchInTheWildData(ctx, cveID)
		if err != nil {
			// Skip and continue
			continue
		}

		if data != nil {
			dataJSON, _ := json.Marshal(data)
			_, err = w.Pool.Exec(ctx, `
				UPDATE cves 
				SET inthewild_data = $1, inthewild_last_updated = NOW() 
				WHERE cve_id = $2
			`, dataJSON, cveID)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to update InTheWild data for %s: %v", cveID, err)
			}
			count++
		} else {
			// Mark as checked even if no data found
			_, _ = w.Pool.Exec(ctx, "UPDATE cves SET inthewild_last_updated = NOW() WHERE cve_id = $1", cveID)
		}

		// "Slow Sync" - Throttle to respect API limits (1.5s delay)
		time.Sleep(1500 * time.Millisecond)
	}

	w.updateTaskStats(ctx, "inthewild_sync")
	log.Printf("Worker: [SYNC] InTheWild.io synchronization complete. Processed %d records.", count)
}

func (w *Worker) fetchInTheWildData(ctx context.Context, cveID string) (map[string]interface{}, error) {
	baseURL := "https://inthewild.io/api/v1/vulns"
	if envURL := os.Getenv("INTHEWILD_API_URL"); envURL != "" {
		baseURL = envURL
	}
	url := fmt.Sprintf("%s/%s", baseURL, cveID)
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
		return nil, fmt.Errorf("InTheWild API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Ensure we only return data if it actually contains exploitation info
	// InTheWild sometimes returns an empty-ish response for non-exploited vulns
	return result, nil
}
