package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorker_ExploitDetection(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	w := &Worker{Pool: mock}

	entries := []NVDCVEEntry{
		{
			CVE: NVDCVE{
				ID: "CVE-EXPLOIT",
				Descriptions: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{
					{Lang: "en", Value: "Exploitable"},
				},
				References: []struct {
					URL  string   `json:"url"`
					Tags []string `json:"tags"`
				}{
					{URL: "https://www.exploit-db.com/exploits/1", Tags: []string{"Exploit"}},
				},
				Published:    time.Now().Format(time.RFC3339),
				LastModified: time.Now().Format(time.RFC3339),
			},
		},
	}

	// Expect UPSERT with 14 arguments (including reference_tags as 13th argument and exploit_available as arg 14)
	mock.ExpectBegin()
	mock.ExpectQuery("(?i)INSERT INTO cves").
		WithArgs(
			"CVE-EXPLOIT", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
			pgxmock.AnyArg(), // reference_tags (13th argument)
			true,             // ExploitAvailable (14th argument)
		).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	if err := w.upsertCVEs(context.Background(), entries, true); err != nil {
		t.Fatalf("upsertCVEs failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Exploit detection failed expectations: %v", err)
	}
}

func TestWorker_InTheWildSync(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{"exploitation": "confirmed"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	t.Setenv("INTHEWILD_API_URL", ts.URL)

	w := &Worker{Pool: mock, HTTP: ts.Client()}
	ctx := context.Background()

	mock.ExpectQuery("SELECT cve_id FROM cves").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2024-TEST"))

	// Expect the data update
	mock.ExpectExec("UPDATE cves SET inthewild_data").
		WithArgs(pgxmock.AnyArg(), "CVE-2024-TEST").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	// Expect the final task stats update
	mock.ExpectExec("INSERT INTO worker_sync_stats").
		WithArgs("inthewild_sync").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	w.syncInTheWild(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("InTheWild sync failed expectations: %v", err)
	}
}
