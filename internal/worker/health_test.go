package worker

import (
	"context"
	"errors"
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
		mock.ExpectQuery("SELECT COUNT(.*) FROM notification_delivery_logs").WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
		tasks := []string{"nvd_sync", "cisa_kev_sync", "epss_sync", "github_buzz_sync", "osv_sync", "greynoise_sync"}
		for _, task := range tasks {
			mock.ExpectQuery("SELECT last_run FROM worker_sync_stats").WithArgs(task).WillReturnError(errors.New("no rows"))
		}
		
		mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("health_check").WillReturnResult(pgxmock.NewResult("INSERT", 1))

		w.checkWorkerHealth(context.Background())

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("startHealthCheckPeriodically", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w.startHealthCheckPeriodically(ctx)
	})
}
