package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

var defaultThreatIntelURL = "https://raw.githubusercontent.com/intel-threat/ransomware-cve-map/main/map.json"

type ThreatIntelFeed struct {
	Associations []struct {
		CVEID      string `json:"cve_id"`
		EntityName string `json:"entity_name"`
		EntityType string `json:"entity_type"` // "threat_actor" or "ransomware"
		Source     string `json:"source"`
	} `json:"associations"`
}

func (w *Worker) syncThreatIntelPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "threat_intel_sync", 24*time.Hour, 5*time.Minute)
	w.syncThreatIntel(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncThreatIntel(ctx)
		}
	}
}

func (w *Worker) syncThreatIntel(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting Threat Intel synchronization...")
	
	// Curated built-in associations as baseline / fallback
	curatedAssociations := []models.ThreatAssociation{
		{CVEID: "CVE-2021-34473", EntityName: "Lazarus Group", EntityType: "threat_actor", Source: "MITRE CTI"},
		{CVEID: "CVE-2021-34473", EntityName: "LockBit", EntityType: "ransomware", Source: "CISA StopRansomware"},
		{CVEID: "CVE-2021-44228", EntityName: "Lazarus Group", EntityType: "threat_actor", Source: "MITRE CTI"},
		{CVEID: "CVE-2021-44228", EntityName: "Conti", EntityType: "ransomware", Source: "CISA StopRansomware"},
		{CVEID: "CVE-2019-11510", EntityName: "REvil", EntityType: "ransomware", Source: "CISA StopRansomware"},
		{CVEID: "CVE-2019-11510", EntityName: "APT29", EntityType: "threat_actor", Source: "MITRE CTI"},
		{CVEID: "CVE-2020-0601", EntityName: "APT41", EntityType: "threat_actor", Source: "MITRE CTI"},
		{CVEID: "CVE-2023-38831", EntityName: "Sandworm", EntityType: "threat_actor", Source: "MITRE CTI"},
		{CVEID: "CVE-2023-38831", EntityName: "CL0P", EntityType: "ransomware", Source: "CISA StopRansomware"},
		{CVEID: "CVE-2023-23397", EntityName: "APT28", EntityType: "threat_actor", Source: "MITRE CTI"},
		{CVEID: "CVE-2023-4966", EntityName: "LockBit", EntityType: "ransomware", Source: "CISA StopRansomware"},
	}

	var associations []models.ThreatAssociation

	// Attempt to download the latest threat intel feed
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(timeoutCtx, "GET", defaultThreatIntelURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel-Bot/1.0")
		resp, err := w.HTTP.Do(req)
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
				if err == nil {
					var feed ThreatIntelFeed
					if err := json.Unmarshal(bodyBytes, &feed); err == nil && len(feed.Associations) > 0 {
						log.Printf("Worker: [SYNC] Successfully fetched %d Threat Intel associations from feed", len(feed.Associations))
						for _, a := range feed.Associations {
							if a.CVEID == "" || a.EntityName == "" || a.EntityType == "" || a.Source == "" {
								log.Printf("Worker: [WARN] Skipping threat association with empty required fields: CVEID=%q, EntityName=%q, EntityType=%q, Source=%q", a.CVEID, a.EntityName, a.EntityType, a.Source)
								continue
							}
							if a.EntityType != "threat_actor" && a.EntityType != "ransomware" {
								log.Printf("Worker: [WARN] Skipping threat association with invalid EntityType: %q", a.EntityType)
								continue
							}
							associations = append(associations, models.ThreatAssociation{
								CVEID:      a.CVEID,
								EntityName: a.EntityName,
								EntityType: a.EntityType,
								Source:     a.Source,
							})
						}
					} else {
						log.Printf("Worker: [WARN] Failed to unmarshal Threat Intel feed: %v. Using curated fallback.", err)
					}
				}
			} else {
				log.Printf("Worker: [WARN] Threat Intel feed returned status %d. Using curated fallback.", resp.StatusCode)
			}
		} else {
			log.Printf("Worker: [WARN] Failed to fetch Threat Intel feed: %v. Using curated fallback.", err)
		}
	}

	// Always overlay curated fallback items to ensure baseline data is present
	for _, ca := range curatedAssociations {
		found := false
		for _, a := range associations {
			if a.CVEID == ca.CVEID && a.EntityName == ca.EntityName && a.EntityType == ca.EntityType {
				found = true
				break
			}
		}
		if !found {
			associations = append(associations, ca)
		}
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to start Threat Intel transaction: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, assoc := range associations {
		_, err := tx.Exec(ctx, `
			INSERT INTO cve_threat_associations (cve_id, entity_name, entity_type, source)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (cve_id, entity_name, entity_type) DO NOTHING
		`, assoc.CVEID, assoc.EntityName, assoc.EntityType, assoc.Source)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to insert threat association for %s: %v", assoc.CVEID, err)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("Worker: [ERROR] Failed to commit Threat Intel transaction: %v", err)
		return
	}

	w.updateTaskStats(ctx, "threat_intel_sync")
	log.Printf("Worker: [SYNC] Threat Intel synchronization complete. Processed %d associations.", len(associations))
}
