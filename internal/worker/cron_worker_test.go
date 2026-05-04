package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
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

		mock.ExpectQuery("SELECT id, cve_id, description, configurations FROM cves").WillReturnRows(
			pgxmock.NewRows([]string{"id", "cve_id", "description", "configurations"}).
				AddRow(1, "CVE-123", "test", json.RawMessage(`[]`)),
		)
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
		
		// startWeeklySummaryTask calls runWeeklySummaryWithLock(ctx)
		// which calls Begin(ctx). If ctx is canceled, Begin might return error immediately.
		mock.ExpectBegin().WillReturnError(context.Canceled)
		
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
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		
		// waitUntilNextRun is called first
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats").WithArgs("intelligence_enrichment").WillReturnRows(pgxmock.NewRows([]string{"last_run"}).AddRow(time.Now()))
		// enrichMissingIntelligence is called next
		mock.ExpectQuery("SELECT id, cve_id, description, configurations FROM cves").WillReturnError(context.Canceled)
		
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
