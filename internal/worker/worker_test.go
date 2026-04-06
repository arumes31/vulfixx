package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"os"
	"testing"
	"time"
)

func TestWorkerIntegration(t *testing.T) {
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

	ctx := context.Background()

	// Seed dummy user
	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, password_hash, is_email_verified) VALUES ('test_worker@example.com', 'hash', TRUE)")
	if err != nil {
		t.Fatalf("Failed to seed user: %v", err)
	}
	var userID int
	err = db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = 'test_worker@example.com'").Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to get seed user id: %v", err)
	}

	// Seed subscription
	_, err = db.Pool.Exec(ctx, "INSERT INTO user_subscriptions (user_id, keyword, min_severity) VALUES ($1, 'test', 5.0)", userID)
	if err != nil {
		t.Fatalf("Failed to seed subscription: %v", err)
	}

	cve := &models.CVE{
		ID:            1000,
		CVEID:         "CVE-WORKER-TEST",
		Description:   "This is a test description",
		CVSSScore:     9.0,
		PublishedDate: time.Now(),
		UpdatedDate:   time.Now(),
	}

	_, err = db.Pool.Exec(ctx, "INSERT INTO cves (cve_id, description, cvss_score, published_date, updated_date) VALUES ($1, $2, $3, $4, $5)", cve.CVEID, cve.Description, cve.CVSSScore, cve.PublishedDate, cve.UpdatedDate)
	if err != nil {
		t.Fatalf("Failed to seed cve: %v", err)
	}

	evaluateSubscriptions(ctx, cve)

	// Direct calls
	sendAlert(models.UserSubscription{WebhookURL: "http://localhost:9999", UserID: userID}, cve, "test_worker@example.com")
	sendVerificationEmail("test_worker@example.com", "dummy_token")
}
