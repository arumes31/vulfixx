package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"cve-tracker/internal/models"

	"github.com/jackc/pgx/v5"
)

const osvConcurrency = 10

type osvResponse struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func (w *Worker) syncOSVPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "osv_sync", 12*time.Hour, 3*time.Minute)
	w.runWithLock(ctx, "osv_sync", 30*time.Minute, w.syncOSV)

	ticker := w.TickerFactory(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "osv_sync", 30*time.Minute, w.syncOSV)
		}
	}
}

type updateItem struct {
	cve     models.CVE
	osvData *osvResponse
	hasData bool
	changed bool
}

func (w *Worker) syncOSV(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting OSV (Open Source Vulnerabilities) synchronization...")

	// Prioritize CVEs that haven't been checked yet, then oldest ones (older than 30 days)
	rows, err := w.Pool.Query(ctx, `
		SELECT id, cve_id, vendor, product, affected_products FROM cves
		WHERE osv_last_updated IS NULL OR osv_last_updated < NOW() - INTERVAL '30 days'
		ORDER BY osv_last_updated ASC NULLS FIRST
		LIMIT 200
	`)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch CVEs for OSV sync", "error", err)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var cve models.CVE
		if err := rows.Scan(&cve.ID, &cve.CVEID, &cve.Vendor, &cve.Product, &cve.AffectedProducts); err == nil {
			cves = append(cves, cve)
		}
	}

	if len(cves) == 0 {
		w.updateTaskStats(ctx, "osv_sync")
		return
	}

	var updates []updateItem
	var mu sync.Mutex
	var wg sync.WaitGroup
	cveChan := make(chan models.CVE, len(cves))

	// Start workers
	for i := 0; i < osvConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cve := range cveChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				osvData, err := w.fetchOSVData(ctx, cve.CVEID)
				if err != nil {
					continue
				}

				item := updateItem{cve: cve, osvData: osvData}
				if osvData != nil {
					item.hasData = true
					// Deep Enrichment: Extract products and versions
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

						item.cve.AddAffectedProduct(vendor, product, versionStr, false)

						// If primary vendor/product is missing, use OSV as authoritative
						if item.cve.Vendor == "" {
							item.cve.Vendor = vendor
						}
						if item.cve.Product == "" {
							item.cve.Product = product
						}
						item.changed = true
					}
				}
				mu.Lock()
				updates = append(updates, item)
				mu.Unlock()
				// Reduced sleep since we are concurrent but still want to be polite
				time.Sleep(50 * time.Millisecond)
			}
		}()
	}

	// Feed workers
	for _, cve := range cves {
		cveChan <- cve
	}
	close(cveChan)
	wg.Wait()

	if len(updates) == 0 {
		w.updateTaskStats(ctx, "osv_sync")
		return
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to begin transaction for OSV updates", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	count := 0
	batch := &pgx.Batch{}
	for _, item := range updates {
		if item.hasData && item.changed {
			dataJSON, marshalErr := json.Marshal(item.osvData)
			if marshalErr != nil {
				slog.Error("Worker: [ERROR] Failed to marshal OSV data in batch", "error", marshalErr, "cve_id", item.cve.CVEID, "osvData", item.osvData)
				continue
			}
			batch.Queue("UPDATE cves SET osv_data = $1, osv_last_updated = NOW(), vendor = $2, product = $3, affected_products = $4 WHERE id = $5",
				dataJSON, item.cve.Vendor, item.cve.Product, item.cve.AffectedProducts, item.cve.ID)
		} else {
			batch.Queue("UPDATE cves SET osv_last_updated = NOW() WHERE id = $1", item.cve.ID)
		}
	}

	br := tx.SendBatch(ctx, batch)
	if br != nil {
		for i := 0; i < len(updates); i++ {
			if _, err := br.Exec(); err == nil {
				count++
			}
		}
		_ = br.Close()
	} else {
		// Fallback for mocks/drivers that don't support batching
		for _, item := range updates {
			var err error
			if item.hasData && item.changed {
				dataJSON, marshalErr := json.Marshal(item.osvData)
				if marshalErr != nil {
					slog.Error("Worker: [ERROR] Failed to marshal OSV data in fallback", "error", marshalErr, "cve_id", item.cve.CVEID, "osvData", item.osvData)
					continue
				}
				_, err = tx.Exec(ctx, "UPDATE cves SET osv_data = $1, osv_last_updated = NOW(), vendor = $2, product = $3, affected_products = $4 WHERE id = $5",
					dataJSON, item.cve.Vendor, item.cve.Product, item.cve.AffectedProducts, item.cve.ID)
			} else {
				_, err = tx.Exec(ctx, "UPDATE cves SET osv_last_updated = NOW() WHERE id = $1", item.cve.ID)
			}
			if err == nil {
				count++
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: [ERROR] Failed to commit OSV updates", "error", err)
	}

	w.updateTaskStats(ctx, "osv_sync")
	slog.Info("Worker: [SYNC] OSV synchronization complete.", "updated_count", count)
}

func (w *Worker) fetchOSVData(ctx context.Context, cveID string) (*osvResponse, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", cveID)
	resp, err := w.doRequest(ctx, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
		Label:       "OSV Fetch",
	}, "GET", url, nil)
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
