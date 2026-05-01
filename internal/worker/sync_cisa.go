package worker

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

var defaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type CISAKEVResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func (w *Worker) fetchCISAKEVPeriodically(ctx context.Context) {
	w.fetchFromCISAKEV(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.fetchFromCISAKEV(ctx)
		}
	}
}

func (w *Worker) fetchFromCISAKEV(ctx context.Context) {
	log.Println("Worker: [SYNC] Fetching CISA KEV catalog...")
	req, err := http.NewRequestWithContext(ctx, "GET", defaultCISAKEVURL, nil)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to create CISA KEV request: %v", err)
		return
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CISA KEV: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Worker: [ERROR] CISA KEV API returned status %d", resp.StatusCode)
		return
	}

	if clStr := resp.Header.Get("Content-Length"); clStr != "" {
		if cl, err := strconv.ParseInt(clStr, 10, 64); err == nil && cl > 50*1024*1024 {
			log.Printf("Worker: [ERROR] CISA KEV feed too large (%d bytes)", cl)
			return
		}
	}

	const maxSize = 50 * 1024 * 1024
	limitReader := io.LimitReader(resp.Body, int64(maxSize)+1)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to read CISA KEV: %v", err)
		return
	}

	if len(bodyBytes) > maxSize {
		log.Printf("Worker: [ERROR] CISA KEV feed exceeded 50MB limit")
		return
	}

	var kevResp CISAKEVResponse
	if err := json.Unmarshal(bodyBytes, &kevResp); err != nil {
		log.Printf("Worker: [ERROR] Failed to unmarshal CISA KEV: %v", err)
		return
	}

	total := len(kevResp.Vulnerabilities)
	log.Printf("Worker: [SYNC] Updating %d CISA KEV records...", total)

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to start KEV transaction: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Optimization: Reset and then set true only for those in the feed
	if _, err := tx.Exec(ctx, "UPDATE cves SET cisa_kev = false WHERE cisa_kev = true"); err != nil {
		log.Printf("Worker: [ERROR] Failed to reset CISA KEV status: %v", err)
		return
	}

	batchSize := 200
	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}
		ids := make([]string, 0, end-i)
		for _, v := range kevResp.Vulnerabilities[i:end] {
			ids = append(ids, v.CVEID)
		}
		_, err := tx.Exec(ctx, "UPDATE cves SET cisa_kev = true WHERE cve_id = ANY($1)", ids)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to update KEV batch: %v", err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		log.Printf("Worker: [ERROR] Failed to commit KEV transaction: %v", err)
		return
	}
	w.updateTaskStats(ctx, "cisa_kev_sync")
	log.Println("Worker: [SYNC] CISA KEV update complete.")
}
