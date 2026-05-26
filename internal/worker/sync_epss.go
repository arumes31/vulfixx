package worker

import (
	"bufio"
	"compress/gzip"
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (w *Worker) syncEPSSPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "epss_sync", 24*time.Hour, 5*time.Minute)
	w.syncEPSS(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.syncEPSS(ctx)
		}
	}
}

var defaultEPSSBaseURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

func (w *Worker) syncEPSS(ctx context.Context) {
	slog.Info("Worker: [SYNC] Starting EPSS score synchronization...")
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", defaultEPSSBaseURL, nil)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to create EPSS bulk request", "error", err)
		return
	}
	req.Header.Set("User-Agent", "Vulfixx-Threat-Intel-Bot/1.0")

	resp, err := w.HTTP.Do(req)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to download EPSS bulk CSV", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Worker: [ERROR] EPSS bulk CSV returned error status", "status", resp.StatusCode)
		return
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to create gzip reader for EPSS CSV", "error", err)
		return
	}
	defer func() { _ = gzReader.Close() }()

	scanner := bufio.NewScanner(gzReader)
	var batchRows [][]interface{}
	batchSize := 5000
	totalProcessed := 0
	parseErrorCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "cve,") {
			continue // Skip headers
		}

		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			cveID := strings.TrimSpace(parts[0])
			scoreStr := strings.TrimSpace(parts[1])
			score, err := strconv.ParseFloat(scoreStr, 64)
			if err == nil {
				batchRows = append(batchRows, []interface{}{cveID, score})
				totalProcessed++
			} else {
				parseErrorCount++
				if parseErrorCount < 5 {
					slog.Debug("Worker: [DEBUG] Failed to parse EPSS score", "score_str", scoreStr, "cve_id", cveID, "error", err)
				}
			}
		}

		if len(batchRows) >= batchSize {
			w.updateEPSSBatch(ctx, batchRows)
			batchRows = batchRows[:0]
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}

	if len(batchRows) > 0 {
		w.updateEPSSBatch(ctx, batchRows)
	}

	if err := scanner.Err(); err != nil {
		slog.Error("Worker: [ERROR] EPSS CSV scanner error", "error", err)
		return
	}

	w.updateTaskStats(ctx, "epss_sync")
	slog.Info("Worker: [SYNC] EPSS score synchronization complete.", "processed_count", totalProcessed, "duration", time.Since(start))
}

func (w *Worker) updateEPSSBatch(ctx context.Context, batch [][]interface{}) {
	cveIDs := make([]string, len(batch))
	scores := make([]float64, len(batch))

	for i, row := range batch {
		cveIDs[i] = row[0].(string)
		scores[i] = row[1].(float64)
	}

	query := `
		UPDATE cves 
		SET epss_score = u.epss_score
		FROM (SELECT unnest($1::text[]) as cve_id, unnest($2::numeric[]) as epss_score) as u
		WHERE cves.cve_id = u.cve_id 
		AND cves.epss_score IS DISTINCT FROM u.epss_score
	`
	_, err := w.Pool.Exec(ctx, query, cveIDs, scores)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to bulk update EPSS scores", "error", err)
	}
}
