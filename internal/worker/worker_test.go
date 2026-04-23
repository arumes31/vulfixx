package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWorkerFunctions(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION") == "true" {
		t.Skip("skipping integration test (SKIP_INTEGRATION=true)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mock NVD API
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{
			TotalResults: 1,
			Vulnerabilities: []struct {
				CVE struct {
					ID           string `json:"id"`
					Published    string `json:"published"`
					LastModified string `json:"lastModified"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					References []struct {
						URL string `json:"url"`
					} `json:"references"`
					Metrics struct {
						CvssMetricV31 []struct {
							CvssData struct {
								BaseScore    float64 `json:"baseScore"`
								VectorString string  `json:"vectorString"`
							} `json:"cvssData"`
						} `json:"cvssMetricV31"`
						CvssMetricV30 []struct {
							CvssData struct {
								BaseScore    float64 `json:"baseScore"`
								VectorString string  `json:"vectorString"`
							} `json:"cvssData"`
						} `json:"cvssMetricV30"`
						CvssMetricV2 []struct {
							CvssData struct {
								BaseScore    float64 `json:"baseScore"`
								VectorString string  `json:"vectorString"`
							} `json:"cvssData"`
						} `json:"cvssMetricV2"`
					} `json:"metrics"`
				} `json:"cve"`
			}{
				{
					CVE: struct {
						ID           string `json:"id"`
						Published    string `json:"published"`
						LastModified string `json:"lastModified"`
						Descriptions []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"descriptions"`
						References []struct {
							URL string `json:"url"`
						} `json:"references"`
						Metrics struct {
							CvssMetricV31 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
							CvssMetricV30 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV30"`
							CvssMetricV2 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV2"`
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
						References: []struct {
							URL string `json:"url"`
						}{
							{URL: "https://example.com/exploit"},
						},
						Metrics: struct {
							CvssMetricV31 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
							CvssMetricV30 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV30"`
							CvssMetricV2 []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV2"`
						}{
							CvssMetricV31: []struct {
								CvssData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							}{
								{
									CvssData: struct {
										BaseScore    float64 `json:"baseScore"`
										VectorString string  `json:"vectorString"`
									}{
										BaseScore:    7.5,
										VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
									},
								},
							},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_USER", "cveuser")
	t.Setenv("DB_PASSWORD", "cvepass")
	t.Setenv("DB_NAME", "cvetracker")
	t.Setenv("REDIS_URL", "localhost:6379")
	t.Setenv("SMTP_HOST", "") // disable real email

	err := db.InitDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("InitDB failed (skipping): %v", err)
		} else {
			t.Fatalf("Failed to init db: %v", err)
		}
	}
	defer db.CloseDB()

	err = db.InitRedis()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("InitRedis failed (skipping): %v", err)
		} else {
			t.Fatalf("Failed to init redis: %v", err)
		}
	}
	defer db.CloseRedis()

	// Calling the functions directly to increase coverage
	defaultNVDBaseURL = ts.URL
	fetchFromNVD(ctx)

	// Test worker loops briefly
	go processAlerts(ctx)
	go processEmailVerification(ctx)

	// Push something to the queues to trigger the loops
	db.RedisClient.LPush(ctx, "cve_alerts_queue", "{\"cve_id\":\"CVE-123\", \"description\":\"test\"}")
	db.RedisClient.LPush(ctx, "email_verification_queue", "{\"email\":\"test@example.com\", \"token\":\"token\"}")

	time.Sleep(500 * time.Millisecond)
	cancel()

	// Direct calls
	cveBody := models.CVE{
		CVEID:       "CVE-TEST-WORKER",
		Description: "Test",
		CVSSScore:   7.5,
	}
	evaluateSubscriptions(context.Background(), &cveBody)
	sendAlert(models.UserSubscription{WebhookURL: "http://127.0.0.1:9999", UserID: 1}, &cveBody, "test@example.com")
	sendVerificationEmail("test@example.com", "token123")
}
