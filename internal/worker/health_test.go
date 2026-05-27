package worker

import (
	"context"
	"net/http"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorker_health_Coverage(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

	t.Run("checkWorkerHealth", func(t *testing.T) {
		tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync", "inthewild_sync", "threat_intel_sync", "advisory_rss_sync", "intelligence_sync", "intelligence_enrichment", "health_check"}

		// Expectation for checkNotificationHealth
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM notification_delivery_logs").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		// Expectation for optimized query in checkWorkerHealth
		mock.ExpectQuery("SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY\\(\\$1\\)").
			WithArgs(tasks).
			WillReturnRows(pgxmock.NewRows([]string{"task_name", "last_run"}))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("health_check").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.checkWorkerHealth(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("startHealthCheckPeriodically", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync", "inthewild_sync", "threat_intel_sync", "advisory_rss_sync", "intelligence_sync", "intelligence_enrichment", "health_check"}

		// startHealthCheckPeriodically calls waitUntilNextRun first
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = \\$1").
			WithArgs("health_check").
			WillReturnRows(pgxmock.NewRows([]string{"last_run"}))

		// Then calls checkWorkerHealth
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM notification_delivery_logs").
			WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

		mock.ExpectQuery("SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY\\(\\$1\\)").
			WithArgs(tasks).
			WillReturnRows(pgxmock.NewRows([]string{"task_name", "last_run"}))

		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("health_check").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.startHealthCheckPeriodically(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})
}
