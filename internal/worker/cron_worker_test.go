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

		mock.ExpectQuery("(?i)SELECT id, cve_id, description, configurations, \"references\" FROM cves WHERE vendor IS NULL OR vendor = '' OR product IS NULL OR product = '' ORDER BY cvss_score DESC, cisa_kev DESC LIMIT 1000").WillReturnRows(
			pgxmock.NewRows([]string{"id", "cve_id", "description", "configurations", "references"}).
				AddRow(1, "CVE-123", "test", json.RawMessage(`[]`), []string{}),
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

		// Successful delivery must report no error so the caller records the run.
		if err := w.sendWeeklySummaries(context.Background()); err != nil {
			t.Errorf("expected nil error on success, got %v", err)
		}

		// A cancelled context must propagate failure so the run is NOT recorded,
		// guarding against a silent no-op that always "succeeds".
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := w.sendWeeklySummaries(ctx); err == nil {
			t.Error("expected error when context is cancelled, got nil")
		}
	})
}

func TestEnrichSingleCVE(t *testing.T) {
	tests := []struct {
		name  string
		cveID int
		setup func(mock pgxmock.PgxPoolIface, id int)
	}{
		{
			name:  "Query Error",
			cveID: 1,
			setup: func(m pgxmock.PgxPoolIface, id int) {
				m.ExpectQuery("SELECT id, cve_id, description, configurations, \"references\" FROM cves WHERE id = \\$1").
					WithArgs(id).
					WillReturnError(sql.ErrConnDone)
			},
		},
		{
			name:  "Success No Rows",
			cveID: 2,
			setup: func(m pgxmock.PgxPoolIface, id int) {
				rows := pgxmock.NewRows([]string{"id", "cve_id", "description", "configurations", "references"})
				m.ExpectQuery("SELECT id, cve_id, description, configurations, \"references\" FROM cves WHERE id = \\$1").
					WithArgs(id).
					WillReturnRows(rows)
			},
		},
		{
			name:  "Success Single Row",
			cveID: 3,
			setup: func(m pgxmock.PgxPoolIface, id int) {
				configData, _ := json.Marshal(map[string]interface{}{"nodes": []interface{}{}})
				refData, _ := json.Marshal([]map[string]string{{"url": "http://example.com"}})

				rows := pgxmock.NewRows([]string{"id", "cve_id", "description", "configurations", "references"}).
					AddRow(id, "CVE-2023-1234", "A description", configData, refData)
				m.ExpectQuery("SELECT id, cve_id, description, configurations, \"references\" FROM cves WHERE id = \\$1").
					WithArgs(id).
					WillReturnRows(rows)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("failed to create mock pool: %v", err)
			}
			defer mock.Close()

			w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
			ctx := context.Background()

			tt.setup(mock, tt.cveID)
			w.enrichSingleCVE(ctx, tt.cveID)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
