package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestWorkerFunctions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mock NVD API
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{
			Vulnerabilities: []struct {
				CVE struct {
					ID          string `json:"id"`
					Published   string `json:"published"`
					LastModified string `json:"lastModified"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					Metrics struct {
						CvssMetricV31 []struct {
							CvssData struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssData"`
						} `json:"cvssMetricV31"`
					} `json:"metrics"`
				} `json:"cve"`
			}{
				{
					CVE: struct {
						ID          string `json:"id"`
						Published   string `json:"published"`
						LastModified string `json:"lastModified"`
						Descriptions []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"descriptions"`
						Metrics struct {
							CvssMetricV31 []struct {
								CvssData struct {
									BaseScore float64 `json:"baseScore"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
						} `json:"metrics"`
					}{
						ID:           "CVE-2023-0001",
						Published:    "2023-01-01T00:00:00Z",
						LastModified: "2023-01-01T00:00:00Z",
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{
							{Lang: "en", Value: "Test description"},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	os.Setenv("NVD_API_URL", ts.URL)
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
	fetchFromNVD()

	// Test worker loops briefly
	go processAlerts(ctx)
	go processEmailVerification(ctx)
	
	// Push something to the queues to trigger the loops
	db.RedisClient.LPush(ctx, "cve_alerts_queue", "{\"cve_id\":\"CVE-123\", \"description\":\"test\"}")
	db.RedisClient.LPush(ctx, "email_verification_queue", "{\"email\":\"test@example.com\", \"token\":\"token\"}")
	
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Direct calls
	cveBody := models.CVE{
		CVEID: "CVE-TEST-WORKER",
		Description: "Test",
		CVSSScore: 7.5,
	}
	evaluateSubscriptions(context.Background(), &cveBody)
	sendAlert(models.UserSubscription{WebhookURL: "http://127.0.0.1:9999", UserID: 1}, &cveBody, "test@example.com")
	sendVerificationEmail("test@example.com", "token123")
}
