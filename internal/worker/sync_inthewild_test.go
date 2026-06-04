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

	// Disable order verification for concurrent execution
	mock.MatchExpectationsInOrder(false)

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup test redis: %v", err)
	}
	defer mr.Close()

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

		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET inthewild_data = $1, inthewild_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(pgxmock.AnyArg(), "CVE-ITW-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("inthewild_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		w.syncInTheWild(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("NoData_StillMarksAsChecked", func(t *testing.T) {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves WHERE (inthewild_last_updated IS NULL OR inthewild_last_updated < NOW() - INTERVAL '30 days') AND cve_id ~ '^CVE-\\d{4}-\\d+$' ORDER BY inthewild_last_updated ASC NULLS FIRST LIMIT 100")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-ITW-NONE"))

		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET inthewild_last_updated = NOW() WHERE cve_id = $1")).
			WithArgs("CVE-ITW-NONE").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("inthewild_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		w.syncInTheWild(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestWorkerSync_InTheWild_Concurrent(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"exploited":true}`)),
			}, nil
		},
	}
	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

	// Test with 3 CVEs
	mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves")).
		WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).
			AddRow("CVE-2024-0001").
			AddRow("CVE-2024-0002").
			AddRow("CVE-2024-0003"))

	mock.ExpectBegin()
	for i := 1; i <= 3; i++ {
		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET inthewild_data = $1, inthewild_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	}
	mock.ExpectCommit()

	mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("inthewild_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w.syncInTheWild(ctx)
	duration := time.Since(start)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}

	// We have 3 CVEs.
	// Using rate.Limiter, the first request proceeds immediately.
	// The next 2 will take at least 2 * 1.5s = 3.0s.
	// So 3.0s is the expected minimum duration. We use 2.8s to account for slight timing variances.
	if duration < 2800*time.Millisecond {
		t.Errorf("Rate limiting might not be working, duration too short: %v", duration)
	}
}
