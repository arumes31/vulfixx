package worker

import (
	"context"
	"cve-tracker/internal/db"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorkerSync_InTheWild(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "CVE-ITW-1") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"id":"CVE-ITW-1","exploited":true}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		},
	}
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE (inthewild_last_updated IS NULL OR inthewild_last_updated < NOW() - INTERVAL '30 days') AND cve_id ~ '^CVE-\\d{4}-\\d+$' ORDER BY inthewild_last_updated ASC NULLS FIRST LIMIT 100")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-ITW-1"))
		
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET inthewild_data = $1, inthewild_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(pgxmock.AnyArg(), "CVE-ITW-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("inthewild_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncInTheWild(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("NoData_StillMarksAsChecked", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE (inthewild_last_updated IS NULL OR inthewild_last_updated < NOW() - INTERVAL '30 days') AND cve_id ~ '^CVE-\\d{4}-\\d+$' ORDER BY inthewild_last_updated ASC NULLS FIRST LIMIT 100")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-ITW-NONE"))
		
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET inthewild_last_updated = NOW() WHERE cve_id = $1")).
			WithArgs("CVE-ITW-NONE").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("inthewild_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.syncInTheWild(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
