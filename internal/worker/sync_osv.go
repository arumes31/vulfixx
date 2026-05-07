package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cve-tracker/internal/models"
)

type osvResponse struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func (w *Worker) syncOSVPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "osv_sync", 12*time.Hour, 3*time.Minute)
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

	// Prioritize CVEs that haven't been checked yet, then oldest ones (older than 30 days)
	rows, err := w.Pool.Query(ctx, `
		SELECT cve_id FROM cves 
		WHERE osv_last_updated IS NULL OR osv_last_updated < NOW() - INTERVAL '30 days'
		ORDER BY osv_last_updated ASC NULLS FIRST
		LIMIT 200
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
			// Deep Enrichment: Extract products and versions
			var cve models.CVE
			err = w.Pool.QueryRow(ctx, "SELECT id, vendor, product, affected_products FROM cves WHERE cve_id = $1", cveID).Scan(&cve.ID, &cve.Vendor, &cve.Product, &cve.AffectedProducts)
			if err == nil {
				changed := false
				for _, aff := range osvData.Affected {
					vendor := aff.Package.Ecosystem
					product := aff.Package.Name
					
					// Build version string from ranges
					var versionParts []string
					for _, r := range aff.Ranges {
						var start, end string
						for _, ev := range r.Events {
							if v, ok := ev["introduced"]; ok && v != "0" {
								start = "≥" + v
							}
							if v, ok := ev["fixed"]; ok {
								end = "<" + v
							}
							if v, ok := ev["last_affected"]; ok {
								end = "≤" + v
							}
						}
						if start != "" && end != "" {
							versionParts = append(versionParts, start+" "+end)
						} else if start != "" {
							versionParts = append(versionParts, start)
						} else if end != "" {
							versionParts = append(versionParts, end)
						}
					}
					
					versionStr := strings.Join(versionParts, ", ")
					if versionStr == "" && len(aff.Versions) > 0 {
						// Fallback to first few versions if no ranges
						if len(aff.Versions) > 3 {
							versionStr = strings.Join(aff.Versions[:3], ", ") + "..."
						} else {
							versionStr = strings.Join(aff.Versions, ", ")
						}
					}

					cve.AddAffectedProduct(vendor, product, versionStr, false)
					
					// If primary vendor/product is missing, use OSV as authoritative
					if cve.Vendor == "" {
						cve.Vendor = vendor
						changed = true
					}
					if cve.Product == "" {
						cve.Product = product
						changed = true
					}
					changed = true
				}

				if changed {
					dataJSON, _ := json.Marshal(osvData)
					_, err = w.Pool.Exec(ctx, "UPDATE cves SET osv_data = $1, osv_last_updated = NOW(), vendor = $2, product = $3, affected_products = $4 WHERE id = $5", 
						dataJSON, cve.Vendor, cve.Product, cve.AffectedProducts, cve.ID)
				} else {
					_, _ = w.Pool.Exec(ctx, "UPDATE cves SET osv_last_updated = NOW() WHERE id = $1", cve.ID)
				}
				if err == nil {
					count++
				}
			}
		} else {
			// Mark as checked even if no data found
			_, _ = w.Pool.Exec(ctx, "UPDATE cves SET osv_last_updated = NOW() WHERE cve_id = $1", cveID)
		}

		time.Sleep(200 * time.Millisecond) // OSV is fast
	}
	
	w.updateTaskStats(ctx, "osv_sync")
	log.Printf("Worker: [SYNC] OSV synchronization complete. Updated %d records.", count)
}

func (w *Worker) fetchOSVData(ctx context.Context, cveID string) (*osvResponse, error) {
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

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
