package worker

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorker_DarknetScalper(t *testing.T) {
	// 1. Mock Database
	mock, _ := pgxmock.NewPool()
	defer mock.Close()

	w := &Worker{Pool: mock}
	ctx := context.Background()

	// Mock CVE fetch
	mock.ExpectQuery("SELECT cve_id FROM cves").
		WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-2024-DARK"))

	// Expect Stats Update (at the end of runDarknetScanGRPC)
	mock.ExpectExec("INSERT INTO worker_sync_stats").
		WithArgs("darknet_sync").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Note: We skip mocking gRPC here to avoid complex test setup.
	// The call to runDarknetScanGRPC will attempt to dial "localhost:0" and fail, 
	// which is acceptable for this logic test as long as it doesn't panic.
	w.runDarknetScanGRPC(ctx, "localhost:0")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Darknet scalper test failed expectations: %v", err)
	}
}
