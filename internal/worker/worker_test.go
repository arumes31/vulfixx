package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorkerFunctions(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Mock NVD API
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{
			TotalResults: 1,
			Vulnerabilities: []NVDCVEEntry{
				{
					CVE: NVDCVE{
						ID:           "CVE-2023-0001",
						Published:    time.Now().Format(time.RFC3339),
						LastModified: time.Now().Format(time.RFC3339),
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{
							{Lang: "en", Value: "Test vulnerability"},
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
						Weaknesses: []struct {
							Description []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							} `json:"description"`
						}{
							{
								Description: []struct {
									Lang  string `json:"lang"`
									Value string `json:"value"`
								}{
									{Lang: "en", Value: "CWE-79"},
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

	t.Setenv("SMTP_HOST", "") // disable real email

	// Mock expectations for fetchFromNVD
	mock.ExpectQuery("SELECT value FROM sync_state WHERE key = 'last_nvd_sync'").
		WillReturnError(fmt.Errorf("no sync")) // Trigger full backfill

	mock.ExpectQuery("WITH upsert AS").
		WithArgs("CVE-2023-0001", pgxmock.AnyArg(), 7.5, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "tag"}).AddRow(1, "ins"))

	mock.ExpectExec("INSERT INTO sync_state").
		WithArgs(pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Calling the functions directly to increase coverage
	defaultNVDBaseURL = ts.URL
	fetchFromNVD(ctx)

	// Test evaluateSubscriptions
	mock.ExpectQuery("SELECT s.id, s.user_id").
		WithArgs(7.5, "Test description").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "filter_logic", "email"}).
			AddRow(1, 1, "test", 5.0, "http://example.com/webhook", true, true, "", "test@example.com"))

	// notifyIfNew for first sub
	mock.ExpectExec("INSERT INTO alert_history").WithArgs(1, 1).WillReturnResult(pgxmock.NewResult("INSERT", 1))

	mock.ExpectQuery("SELECT ak.keyword, a.user_id").
		WithArgs("Test description").
		WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email", "name"}).
			AddRow("test", 2, "asset@example.com", "Asset-1"))

	// notifyIfNew for second sub (asset match)
	mock.ExpectExec("INSERT INTO alert_history").WithArgs(2, 1).WillReturnResult(pgxmock.NewResult("INSERT", 1))

	cveBody := models.CVE{
		ID:          1,
		CVEID:       "CVE-2023-0001",
		Description: "Test description",
		CVSSScore:   7.5,
	}
	evaluateSubscriptions(ctx, &cveBody)

	// Test worker loops briefly
	go processAlerts(ctx)
	db.RedisClient.LPush(ctx, "cve_alerts_queue", "{\"id\":1, \"cve_id\":\"CVE-2023-0001\", \"description\":\"test\"}")
	time.Sleep(100 * time.Millisecond)
}

func TestWorkerHelpers(t *testing.T) {
	t.Run("SanitizeEmail", func(t *testing.T) {
		email, err := sanitizeEmail("test@example.com")
		if err != nil || email != "test@example.com" {
			t.Errorf("sanitizeEmail failed: %v, %s", err, email)
		}
		_, err = sanitizeEmail("test@example.com\r\n")
		if err == nil {
			t.Error("expected error for email with CRLF")
		}
		_, err = sanitizeEmail("invalid-email")
		if err == nil {
			t.Error("expected error for invalid email")
		}
	})

	t.Run("RedactToken", func(t *testing.T) {
		if redactToken("1234567890") != "12345678..." {
			t.Errorf("redactToken failed: %s", redactToken("1234567890"))
		}
		if redactToken("123") != "123..." {
			t.Errorf("redactToken failed: %s", redactToken("123"))
		}
		if redactToken("") != "<empty>" {
			t.Errorf("redactToken failed: %s", redactToken(""))
		}
	})

	t.Run("RedactURL", func(t *testing.T) {
		url := "https://user:pass@example.com/path?query=1#frag"
		redacted := redactURL(url)
		if redacted != "https://example.com/" {
			t.Errorf("redactURL failed: %s", redacted)
		}
		if redactURL(":") != "[invalid-url]" {
			t.Errorf("redactURL failed for invalid url")
		}
	})
}
