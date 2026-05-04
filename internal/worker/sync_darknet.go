package worker

import (
	"context"
	"log"
	"time"

	"cve-tracker/internal/worker/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)



func (w *Worker) runDarknetScanGRPC(ctx context.Context, target string) {
	log.Printf("Worker: [SYNC] Running Darknet Scalper check via gRPC (%s)...", target)

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Worker: Failed to connect to scalper gRPC (%s): %v", target, err)
		return
	}
	defer conn.Close()

	client := proto.NewScalperServiceClient(conn)

	// Fetch trending or critical CVEs to check
	rows, err := w.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE cvss_score >= 7.0 ORDER BY published_date DESC LIMIT 50")
	if err != nil {
		log.Printf("Worker: Failed to fetch CVEs for darknet check: %v", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			log.Printf("Worker: Failed to scan row: %v", err)
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Worker: Error iterating rows: %v", err)
	}

	// (9) Use Backfill for batch processing with priority
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := client.Backfill(childCtx, &proto.BackfillRequest{
		CveIds:   cveIDs,
		Priority: 8, // High priority for our sync worker
	})

	if err != nil {
		log.Printf("Worker: Failed to queue darknet backfill: %v", err)
		return
	}

	log.Printf("Worker: Successfully queued %d CVEs for darknet scanning (status: %s)", resp.QueuedCount, resp.Status)
	w.updateTaskStats(ctx, "darknet_sync")
}
