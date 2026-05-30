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

func TestWorkerSync_GreyNoise_Enhanced(t *testing.T) {
	// Disable order verification for concurrent execution

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup test redis: %v", err)
	}
	defer mr.Close()

	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		mock.MatchExpectationsInOrder(false)

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "CVE-2024-0001") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"total": 10}`)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2024-0001"))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET greynoise_hits = $1, greynoise_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(10, "CVE-2024-0001").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("greynoise_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w.syncGreyNoise(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("NotFound_MarkAsZeroHits", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		mock.MatchExpectationsInOrder(false)

		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2024-0002"))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET greynoise_hits = $1, greynoise_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(0, "CVE-2024-0002").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("greynoise_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		w.syncGreyNoise(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("RateLimiting", func(t *testing.T) {
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
					Body:       io.NopCloser(strings.NewReader(`{"total": 10}`)),
				}, nil
			},
		}
		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClient)

		// Test with 3 CVEs
		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).
				AddRow("CVE-2024-1001").
				AddRow("CVE-2024-1002").
				AddRow("CVE-2024-1003"))

		for i := 1; i <= 3; i++ {
			mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET greynoise_hits = $1, greynoise_last_updated = NOW() WHERE cve_id = $2")).
				WithArgs(10, pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		}

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("greynoise_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		w.syncGreyNoise(ctx)
		duration := time.Since(start)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}

		// We have 3 CVEs.
		// rate.Limiter is rate.Every(time.Second), 1.
		// 1st req: instant
		// 2nd req: 1s wait
		// 3rd req: 1s wait
		// Total minimum duration: 2s. Use 1.8s for buffer.
		if duration < 1800*time.Millisecond {
			t.Errorf("Rate limiting might not be working, duration too short: %v", duration)
		}
	})

	t.Run("Retry", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("failed to setup mock db: %v", err)
		}
		defer mock.Close()
		mock.MatchExpectationsInOrder(false)

		attempts := 0
		httpClientRetry := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				attempts++
				if attempts < 2 {
					return &http.Response{
						StatusCode: http.StatusTooManyRequests,
						Header:     http.Header{"Retry-After": []string{"1"}},
						Body:       io.NopCloser(strings.NewReader(`too many requests`)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"total": 42}`)),
				}, nil
			},
		}
		wRetry := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, httpClientRetry)

		mock.ExpectQuery(regexp.QuoteMeta("SELECT cve_id FROM cves")).
			WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-RETRY-1"))

		mock.ExpectExec(regexp.QuoteMeta("UPDATE cves SET greynoise_hits = $1, greynoise_last_updated = NOW() WHERE cve_id = $2")).
			WithArgs(42, "CVE-RETRY-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("greynoise_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		wRetry.syncGreyNoise(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}

		if attempts < 2 {
			t.Errorf("Expected at least 2 attempts due to retry, got %d", attempts)
		}
	})
}
