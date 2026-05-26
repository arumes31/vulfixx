package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"io"
	"log/slog"
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
	slog.Info("Worker: [SYNC] Starting Threat Intel synchronization...")
	
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
						slog.Info("Worker: [SYNC] Successfully fetched Threat Intel associations from feed", "count", len(feed.Associations))
						for _, a := range feed.Associations {
							if a.CVEID == "" || a.EntityName == "" || a.EntityType == "" || a.Source == "" {
								slog.Warn("Worker: [WARN] Skipping threat association with empty required fields", "cve_id", a.CVEID, "entity_name", a.EntityName, "entity_type", a.EntityType, "source", a.Source)
								continue
							}
							if a.EntityType != "threat_actor" && a.EntityType != "ransomware" {
								slog.Warn("Worker: [WARN] Skipping threat association with invalid EntityType", "entity_type", a.EntityType, "cve_id", a.CVEID)
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
						slog.Warn("Worker: [WARN] Failed to unmarshal Threat Intel feed. Using curated fallback.", "error", err)
					}
				}
			} else {
				slog.Warn("Worker: [WARN] Threat Intel feed returned error status. Using curated fallback.", "status", resp.StatusCode)
			}
		} else {
			slog.Warn("Worker: [WARN] Failed to fetch Threat Intel feed. Using curated fallback.", "error", err)
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
		slog.Error("Worker: [ERROR] Failed to start Threat Intel transaction", "error", err)
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
			slog.Error("Worker: [ERROR] Failed to insert threat association", "cve_id", assoc.CVEID, "entity", assoc.EntityName, "error", err)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: [ERROR] Failed to commit Threat Intel transaction", "error", err)
		return
	}

	w.updateTaskStats(ctx, "threat_intel_sync")
	slog.Info("Worker: [SYNC] Threat Intel synchronization complete.", "processed_count", len(associations))
}
