package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"cve-tracker/internal/db"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorkerSync_ThreatIntel(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()

		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			resp := ThreatIntelFeed{
				Associations: []struct {
					CVEID      string `json:"cve_id"`
					EntityName string `json:"entity_name"`
					EntityType string `json:"entity_type"`
					Source     string `json:"source"`
				}{
					{
						CVEID:      "CVE-2023-38831",
						EntityName: "Sandworm",
						EntityType: "threat_actor",
						Source:     "MITRE CTI",
					},
				},
			}
			_ = json.NewEncoder(rw).Encode(resp)
		}))
		defer ts.Close()

		oldURL := defaultThreatIntelURL
		defaultThreatIntelURL = ts.URL
		defer func() { defaultThreatIntelURL = oldURL }()

		mock.ExpectBegin()

		// There are 11 curated associations, and the feed item (CVE-2023-38831 / Sandworm) matches one,
		// so there are exactly 11 unique threat association insertions.
		for i := 0; i < 11; i++ {
			mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cve_threat_associations")).
				WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
		}

		mock.ExpectCommit()
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("threat_intel_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.syncThreatIntel(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("FeedFetchFailure", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()

		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		oldURL := defaultThreatIntelURL
		defaultThreatIntelURL = ts.URL
		defer func() { defaultThreatIntelURL = oldURL }()

		mock.ExpectBegin()

		// Should fallback completely to curated items, which has 11 associations.
		for i := 0; i < 11; i++ {
			mock.ExpectExec(regexp.QuoteMeta("INSERT INTO cve_threat_associations")).
				WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
		}

		mock.ExpectCommit()
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("threat_intel_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.syncThreatIntel(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
