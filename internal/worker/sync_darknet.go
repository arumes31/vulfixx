package worker

import (
	"context"
	"log"
	"os"
	"time"

	"cve-tracker/internal/worker/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func (w *Worker) syncDarknetIntelligence(ctx context.Context) {
	scalperGRPC := os.Getenv("SCALPER_GRPC_URL")
	if scalperGRPC == "" {
		scalperGRPC = "scalper:9090"
	}

	w.waitUntilNextRun(ctx, "darknet_sync", 24*time.Hour, 10*time.Minute)
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		w.runDarknetScanGRPC(ctx, scalperGRPC)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func (w *Worker) runDarknetScanGRPC(ctx context.Context, target string) {
	log.Printf("Worker: [SYNC] Running Darknet Scalper check via gRPC (%s)...", target)

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	conn, err := grpc.DialContext(dialCtx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
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
	resp, err := client.Backfill(ctx, &proto.BackfillRequest{
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
