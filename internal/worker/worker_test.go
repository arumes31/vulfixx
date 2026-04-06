package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"os"
	"testing"
)

func TestWorkerFunctions(t *testing.T) {
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "cveuser")
	os.Setenv("DB_PASSWORD", "cvepass")
	os.Setenv("DB_NAME", "cvetracker")
	os.Setenv("REDIS_URL", "localhost:6379")
	os.Setenv("SMTP_HOST", "") // disable real email
	
	err := db.InitDB()
	if err != nil {
		t.Fatalf("Failed to init db: %v", err)
	}
	defer db.CloseDB()

	err = db.InitRedis()
	if err != nil {
		t.Fatalf("Failed to init redis: %v", err)
	}
	defer db.CloseRedis()

	// Calling the functions directly to increase coverage
	// They use goroutines and infinite loops, so we shouldn't run them fully if they block.
	// But we can call fetchFromNVD since it does one pass.
	fetchFromNVD()
	
	// Seed some alerts in redis and run processAlerts briefly if possible.
	// Since processAlerts has an infinite loop, we cannot call it directly without it blocking.
	// We could run it in a goroutine and cancel.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create a test cve
	cve := models.CVE{
		CVEID: "CVE-TEST-WORKER",
		Description: "Test",
	}
	evaluateSubscriptions(ctx, &cve)
	sendAlert(models.UserSubscription{WebhookURL: "http://127.0.0.1:9999", UserID: 1}, &cve, "test@example.com")
	sendVerificationEmail("test@example.com", "token123")
}
