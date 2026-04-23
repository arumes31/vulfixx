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

	"github.com/pashagolub/pgxmock/v3"
)

func TestFetchFromCISAKEV(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CISAKEVResponse{
			Vulnerabilities: []struct {
				CVEID string `json:"cveID"`
			}{
				{CVEID: "CVE-2023-1111"},
				{CVEID: "CVE-2023-2222"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	defaultCISAKEVURL = ts.URL
	
	mock.ExpectExec("UPDATE cves SET cisa_kev = false").WillReturnResult(pgxmock.NewResult("UPDATE", 10))
	mock.ExpectExec("UPDATE cves SET cisa_kev = true WHERE cve_id = ANY").
		WithArgs([]string{"CVE-2023-1111", "CVE-2023-2222"}).
		WillReturnResult(pgxmock.NewResult("UPDATE", 2))

	fetchFromCISAKEV(context.Background())
}

func TestUpsertCVEs(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	ctx := context.Background()
	vulns := []struct {
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
				ID:           "CVE-UPD-TEST",
				Published:    time.Now().Format(time.RFC3339),
				LastModified: time.Now().Format(time.RFC3339),
			},
		},
	}

	mock.ExpectQuery("WITH upsert AS").
		WithArgs("CVE-UPD-TEST", pgxmock.AnyArg(), 0.0, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "tag"}).AddRow(1, "upd"))
	
	ins, upd := upsertCVEs(ctx, vulns, false)
	if ins != 0 || upd != 1 {
		t.Errorf("upsertCVEs failed: got %d ins, %d upd", ins, upd)
	}
}

func TestNVDAPIDelay(t *testing.T) {
	os.Unsetenv("NVD_API_KEY")
	if nvdAPIDelay() != 6500*time.Millisecond {
		t.Errorf("expected 6500ms delay without API key")
	}
	t.Setenv("NVD_API_KEY", "test")
	if nvdAPIDelay() != 700*time.Millisecond {
		t.Errorf("expected 700ms delay with API key")
	}
}

func TestSendAlertWebhook(t *testing.T) {
	// Test safe vs unsafe IP
	sub := models.UserSubscription{
		EnableWebhook: true,
		WebhookURL:    "http://127.0.0.1:8080", // Unsafe loopback
	}
	cve := &models.CVE{CVEID: "CVE-1"}
	if sendAlert(sub, cve, "test@example.com") {
		// Should be false because 127.0.0.1 is unsafe
	}
}
