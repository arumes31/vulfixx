package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	_, _ = db.SetupTestRedis()

	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		resp := CISAKEVResponse{
			Vulnerabilities: []struct {
				CVEID string `json:"cveID"`
			}{
				{CVEID: "CVE-2023-1111"},
				{CVEID: "CVE-2023-2222"},
			},
		}
		_ = json.NewEncoder(rw).Encode(resp)
	}))
	defer ts.Close()

	oldURL := defaultCISAKEVURL
	defaultCISAKEVURL = ts.URL
	defer func() { defaultCISAKEVURL = oldURL }()

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE cves SET cisa_kev = false").WillReturnResult(pgxmock.NewResult("UPDATE", 10))
	mock.ExpectExec("UPDATE cves SET cisa_kev = true WHERE cve_id = ANY").
		WithArgs([]string{"CVE-2023-1111", "CVE-2023-2222"}).
		WillReturnResult(pgxmock.NewResult("UPDATE", 2))
	mock.ExpectCommit()

	w.fetchFromCISAKEV(context.Background())
}

func TestUpsertCVEs(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	_, _ = db.SetupTestRedis()

	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	ctx := context.Background()
	vulns := []NVDCVEEntry{
		{
			CVE: NVDCVE{
				ID:           "CVE-UPD-TEST",
				Published:    time.Now().Format(time.RFC3339),
				LastModified: time.Now().Format(time.RFC3339),
			},
		},
	}

	mock.ExpectExec("INSERT INTO cves").
		WithArgs("CVE-UPD-TEST", pgxmock.AnyArg(), 0.0, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	mock.ExpectQuery("SELECT id FROM cves WHERE cve_id = \\$1").
		WithArgs("CVE-UPD-TEST").
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))

	w.upsertCVEs(ctx, vulns)
}

func TestSendAlertWebhook(t *testing.T) {
	mock, _ := db.SetupTestDB()
	_, _ = db.SetupTestRedis()
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	sub := models.UserSubscription{
		EnableWebhook: true,
		WebhookURL:    "http://127.0.0.1:8080",
	}
	cve := &models.CVE{CVEID: "CVE-1"}
	// This will log a failure but should not panic
	_ = w.sendAlert(sub, cve, "test@example.com", "Asset-1")
}
