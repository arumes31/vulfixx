package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/pashagolub/pgxmock/v3"
	"net/http"
	"testing"
	"time"
)

func TestWorker_cronWorker_Coverage(t *testing.T) {
	t.Run("runWeeklySummaryWithLock", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

		mock.ExpectBegin()
		mock.ExpectQuery("(?i)SELECT pg_try_advisory_xact_lock").WillReturnRows(pgxmock.NewRows([]string{"locked"}).AddRow(true))
		// Simulate sql.ErrNoRows for the last run query
		mock.ExpectQuery("(?i)SELECT value FROM sync_state WHERE key = 'weekly_summary_last_run'").WillReturnError(sql.ErrNoRows)
		mock.ExpectExec("(?i)INSERT INTO sync_state").WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		w.runWeeklySummaryWithLock(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("enrichMissingIntelligence", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

		mock.ExpectQuery("(?i)SELECT id, cve_id, description, configurations, references FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' ORDER BY cvss_score DESC, cisa_kev DESC LIMIT 1000").WillReturnRows(
			pgxmock.NewRows([]string{"id", "cve_id", "description", "configurations", "references"}).
				AddRow(1, "CVE-123", "test", json.RawMessage(`[]`), []string{}),
		)
		mock.ExpectQuery("(?i)SELECT COUNT\\(\\*\\) FROM \\(SELECT id FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' LIMIT 1000\\) sub").WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("intelligence_enrichment").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.enrichMissingIntelligence(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("startWeeklySummaryTask", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		w.startWeeklySummaryTask(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("startIntelligenceEnrichmentTask", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

		// Initial count check
		// The error from previous run was context canceled, so it might not even reach expectations if it returns before them.
		// Wait, startIntelligenceEnrichmentTask check ctx.Err() at the very beginning.

		// Let's use a context that is NOT canceled yet for the first check
		ctx, cancel := context.WithCancel(context.Background())

		mock.ExpectQuery("(?i)SELECT COUNT\\(\\*\\) FROM cves WHERE vendor IS NULL").WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		// Cancel AFTER it should have done the first query but before it enters the loop?
		// Actually, it does the query then enters the loop.

		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		w.startIntelligenceEnrichmentTask(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("sendWeeklySummaries", func(t *testing.T) {
		w := NewWorker(nil, nil, &EmailSenderMock{}, http.DefaultClient)
		err := w.sendWeeklySummaries(context.Background())
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}
