package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var defaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type CISAKEVResponse struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
	} `json:"vulnerabilities"`
}

func (w *Worker) fetchCISAKEVPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "cisa_kev_sync", 24*time.Hour, 5*time.Minute)
	w.runWithLock(ctx, "cisa_kev_sync", 30*time.Minute, w.fetchFromCISAKEV)
	ticker := w.TickerFactory(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			w.runWithLock(ctx, "cisa_kev_sync", 30*time.Minute, w.fetchFromCISAKEV)
		}
	}
}

func (w *Worker) fetchFromCISAKEV(ctx context.Context) {
	slog.Info("Worker: [SYNC] Fetching CISA KEV catalog...")
	req, err := http.NewRequestWithContext(ctx, "GET", defaultCISAKEVURL, nil)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to create CISA KEV request", "error", err)
		return
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch CISA KEV", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Worker: [ERROR] CISA KEV API returned error status", "status", resp.StatusCode)
		return
	}

	if clStr := resp.Header.Get("Content-Length"); clStr != "" {
		if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil && cl > 50*1024*1024 {
			slog.Error("Worker: [ERROR] CISA KEV feed too large", "size_bytes", cl)
			return
		}
	}

	const maxSize = 50 * 1024 * 1024
	limitReader := io.LimitReader(resp.Body, int64(maxSize)+1)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to read CISA KEV body", "error", err)
		return
	}

	if len(bodyBytes) > maxSize {
		slog.Error("Worker: [ERROR] CISA KEV feed exceeded 50MB limit")
		return
	}

	var kevResp CISAKEVResponse
	if err := json.Unmarshal(bodyBytes, &kevResp); err != nil {
		slog.Error("Worker: [ERROR] Failed to unmarshal CISA KEV JSON", "error", err)
		return
	}

	total := len(kevResp.Vulnerabilities)
	slog.Info("Worker: [SYNC] Updating CISA KEV records...", "count", total)

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to start KEV transaction", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Optimization: Reset and then set true only for those in the feed
	if _, err := tx.Exec(ctx, "UPDATE cves SET cisa_kev = false, cisa_ransomware = false WHERE cisa_kev = true OR cisa_ransomware = true"); err != nil {
		slog.Error("Worker: [ERROR] Failed to reset CISA KEV status in DB", "error", err)
		return
	}

	batchSize := 200
	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}
		ids := make([]string, 0, end-i)
		ransomIds := make([]string, 0)
		kevDataMap := make(map[string]models.JSONBMap, end-i)
		for _, v := range kevResp.Vulnerabilities[i:end] {
			ids = append(ids, v.CVEID)
			if strings.EqualFold(v.KnownRansomwareCampaignUse, "known") {
				ransomIds = append(ransomIds, v.CVEID)
			}
			kevDataMap[v.CVEID] = models.JSONBMap{
				"vulnerability_name": v.VulnerabilityName,
				"date_added":         v.DateAdded,
				"short_description":  v.ShortDescription,
				"required_action":    v.RequiredAction,
				"due_date":           v.DueDate,
				"known_ransomware":   v.KnownRansomwareCampaignUse,
				"vendor_project":     v.VendorProject,
				"product":            v.Product,
			}
		}
		_, err := tx.Exec(ctx, "UPDATE cves SET cisa_kev = true WHERE cve_id = ANY($1)", ids)
		if err != nil {
			slog.Error("Worker: [ERROR] Failed to update KEV batch", "error", err)
			return
		}
		if len(ransomIds) > 0 {
			_, err = tx.Exec(ctx, "UPDATE cves SET cisa_ransomware = true WHERE cve_id = ANY($1)", ransomIds)
			if err != nil {
				slog.Error("Worker: [ERROR] Failed to update Ransomware batch", "error", err)
				return
			}
		}
		// Bulk-update cisa_kev_data for the batch in a single statement (unnest
		// pattern, same as the EPSS sync) instead of one UPDATE per row.
		kevIDs := make([]string, 0, len(ids))
		kevJSON := make([]string, 0, len(ids))
		for _, cveID := range ids {
			data, err := json.Marshal(kevDataMap[cveID])
			if err != nil {
				slog.Error("Worker: [ERROR] Failed to marshal KEV data for CVE", "cve_id", cveID, "error", err)
				continue
			}
			kevIDs = append(kevIDs, cveID)
			kevJSON = append(kevJSON, string(data))
		}
		if len(kevIDs) > 0 {
			_, err = tx.Exec(ctx, `
				UPDATE cves SET cisa_kev_data = u.kev_data::jsonb
				FROM (SELECT unnest($1::text[]) AS cve_id, unnest($2::text[]) AS kev_data) AS u
				WHERE cves.cve_id = u.cve_id`, kevIDs, kevJSON)
			if err != nil {
				slog.Error("Worker: [ERROR] Failed to bulk update KEV data batch", "error", err)
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					slog.Error("Worker: [ERROR] Failed to rollback KEV transaction", "error", rollbackErr)
				}
				return
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: [ERROR] Failed to commit KEV transaction", "error", err)
		return
	}
	w.updateTaskStats(ctx, "cisa_kev_sync")
	slog.Info("Worker: [SYNC] CISA KEV update complete.")
}
