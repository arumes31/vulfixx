package worker

import (
	"context"
	"log"
)

func StartWorker(ctx context.Context) {
	log.Println("Worker: Starting background tasks...")

	// Synchronization Tasks
	go fetchCVEsPeriodically(ctx)
	go fetchCISAKEVPeriodically(ctx)
	go syncEPSSPeriodically(ctx)
	go syncGitHubBuzzPeriodically(ctx)

	// Notification & Alert Processing
	go processAlerts(ctx)
	go processEmailVerification(ctx)
	go processEmailChange(ctx)
	go startWeeklySummaryTask(ctx)

	log.Println("Worker: All background goroutines started.")
	<-ctx.Done()
	log.Println("Worker: Stopping background tasks...")
}
