package worker

import (
	"context"
	"cve-tracker/internal/db"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestGetBackfillProgress(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	w := &Worker{Pool: mock}
	ctx := context.Background()

	t.Run("valid row", func(t *testing.T) {
		mock.ExpectQuery("SELECT value FROM sync_state WHERE key = 'nvd_backfill_index'").
			WillReturnRows(pgxmock.NewRows([]string{"value"}).AddRow("42"))

		progress := w.getBackfillProgress(ctx)
		if progress != 42 {
			t.Errorf("expected 42, got %d", progress)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("no rows error", func(t *testing.T) {
		mock.ExpectQuery("SELECT value FROM sync_state WHERE key = 'nvd_backfill_index'").
			WillReturnError(pgx.ErrNoRows)

		progress := w.getBackfillProgress(ctx)
		if progress != 0 {
			t.Errorf("expected 0, got %d", progress)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("invalid integer parsing", func(t *testing.T) {
		mock.ExpectQuery("SELECT value FROM sync_state WHERE key = 'nvd_backfill_index'").
			WillReturnRows(pgxmock.NewRows([]string{"value"}).AddRow("not_an_int"))

		progress := w.getBackfillProgress(ctx)
		if progress != 0 {
			t.Errorf("expected 0, got %d", progress)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}
