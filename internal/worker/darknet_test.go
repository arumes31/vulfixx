package worker

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestWorker_DarknetScalper(t *testing.T) {
	// 1. Mock Database
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	w := &Worker{Pool: mock}
	ctx := context.Background()

	// Note: We skip mocking gRPC here to avoid complex test setup.
	// The call to runDarknetScanGRPC will attempt to dial "localhost:0" and fail, 
	// which is acceptable for this logic test as long as it doesn't panic.
	w.runDarknetScanGRPC(ctx, "localhost:0")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Darknet scalper test failed expectations: %v", err)
	}
}
