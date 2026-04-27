package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

	t.Setenv("SMTP_HOST", "") // disable real email

	// Mock expectations for fetchFromNVD
	mock.ExpectQuery("SELECT value FROM sync_state WHERE key = 'last_nvd_sync'").
		WillReturnError(fmt.Errorf("no sync")) // Trigger full backfill

	mock.ExpectQuery("WITH upsert AS").
		WithArgs("CVE-2023-0001", pgxmock.AnyArg(), 7.5, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "tag"}).AddRow(1, "ins"))

	mock.ExpectExec("INSERT INTO sync_state").
		WithArgs(pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Calling the functions directly to increase coverage
	defaultNVDBaseURL = ts.URL
	fetchFromNVD(ctx)

	// Test evaluateSubscriptions
	mock.ExpectQuery("SELECT s.id, s.user_id").
		WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "keyword", "min_severity", "webhook_url", "enable_email", "enable_webhook", "email"}).
			AddRow(1, 1, "test", 5.0, "http://example.com/webhook", true, true, "test@example.com"))

	// notifyIfNew for first sub
	mock.ExpectQuery("SELECT EXISTS").WithArgs(1, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("INSERT INTO alert_history").WithArgs(1, 1).WillReturnResult(pgxmock.NewResult("INSERT", 1))

	mock.ExpectQuery("SELECT ak.keyword, a.user_id").
		WillReturnRows(pgxmock.NewRows([]string{"keyword", "user_id", "email"}).
			AddRow("test", 2, "asset@example.com"))

	// notifyIfNew for second sub (asset match)
	mock.ExpectQuery("SELECT EXISTS").WithArgs(2, 1).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
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
		email, err := sanitizeEmail("test@example.com\r\n")
		if err != nil || email != "test@example.com" {
			t.Errorf("sanitizeEmail failed: %v, %s", err, email)
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

func TestSanitizeEmail(t *testing.T) {
	valid, err := sanitizeEmail("test@example.com")
	if err != nil || valid != "test@example.com" {
		t.Errorf("Failed to sanitize valid email: %v", err)
	}

	invalid, err := sanitizeEmail("invalid\n email@example.com")
	if err == nil {
		t.Errorf("Expected error for invalid email, got %s", invalid)
	}
}

func TestRedactToken(t *testing.T) {
	token := redactToken("12345678901234567890")
	if !strings.HasPrefix(token, "12345678") {
		t.Errorf("Failed to redact long token, got: %s", token)
	}

	short := redactToken("123")
	if !strings.HasPrefix(short, "123") {
		t.Errorf("Failed to handle short token, got: %s", short)
	}

	empty := redactToken("")
	if empty != "<empty>" {
		t.Errorf("Failed to handle empty token")
	}
}

func TestRedactURL(t *testing.T) {
	u := redactURL("http://user:pass@example.com/path?query=1")
	if strings.Contains(u, "user:pass") {
		t.Errorf("Failed to redact URL, got: %s", u)
	}

	invalid := redactURL(":%^")
	if invalid != "[invalid-url]" {
		t.Errorf("Failed to handle invalid URL, got: %s", invalid)
	}
}

func TestSendMailWithTimeout(t *testing.T) {
	// Attempt to send email to closed port
	err := sendMailWithTimeout("127.0.0.1", "1", "user", "pass", []string{"test@example.com"}, []byte("test"))
	if err == nil {
		t.Errorf("Expected error sending mail to closed port")
	}
}

func TestFetchCVEsPeriodically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defaultNVDBaseURL = "http://localhost:12345"
	go fetchCVEsPeriodically(ctx)
	time.Sleep(100 * time.Millisecond)
}

func TestProcessEmailChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = db.InitRedis()
	defer db.CloseRedis()
	go processEmailChange(ctx)
	db.RedisClient.LPush(ctx, "email_change_queue", "{\"email\":\"test@example.com\", \"token\":\"token\", \"type\":\"old\"}")
	db.RedisClient.LPush(ctx, "email_change_queue", "invalid")
	time.Sleep(100 * time.Millisecond)
}

func TestSendEmailChangeNotification(t *testing.T) {
	// Should fail silently or return error (it logs internally)
	sendEmailChangeNotification("test@example.com", "token123", "old")
}

func TestStartWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go StartWorker(ctx)
	time.Sleep(100 * time.Millisecond)
}
