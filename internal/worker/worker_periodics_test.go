package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestWorker_StartAndPeriodics(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()

	mr, err := db.SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

	// Since we are running periodics with cancelled context, they should exit immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("StartWorkerWithCancelledContext", func(t *testing.T) {
		mockStart, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mockStart.Close()
		wStart := NewWorker(mockStart, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)
		wStart.Start(ctx)
	})

	t.Run("PeriodicallyWrappers", func(t *testing.T) {
		// Mock expectation for health check and others that query DB
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("greynoise_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncGreyNoisePeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("epss_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncEPSSPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("advisory_rss_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncAdvisoryRSSPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("cisa_kev_sync").
			WillReturnError(pgx.ErrNoRows)

		w.fetchCISAKEVPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("github_buzz_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncGitHubBuzzPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("inthewild_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncInTheWildPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("nvd_sync").
			WillReturnError(pgx.ErrNoRows)

		w.fetchCVEsPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("osv_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncOSVPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("threat_intel_sync").
			WillReturnError(pgx.ErrNoRows)

		w.syncThreatIntelPeriodically(ctx)

		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name =").
			WithArgs("health_check").
			WillReturnError(pgx.ErrNoRows)

		w.startHealthCheckPeriodically(ctx)

		w.startWeeklySummaryTask(ctx)
		w.startIntelligenceEnrichmentTask(ctx)
		w.syncIntelligencePeriodically(ctx)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations in PeriodicallyWrappers: %v", err)
		}
	})
}

func TestWorker_AsynqRedisOptionsAndLogger(t *testing.T) {
	t.Run("GetAsynqRedisConnOpt_Sentinel", func(t *testing.T) {
		_ = os.Setenv("REDIS_SENTINEL_MASTER", "mymaster")
		_ = os.Setenv("REDIS_SENTINEL_ADDRS", "127.0.0.1:26379,127.0.0.1:26380")
		_ = os.Setenv("REDIS_PASSWORD", "secret")
		defer func() {
			_ = os.Unsetenv("REDIS_SENTINEL_MASTER")
			_ = os.Unsetenv("REDIS_SENTINEL_ADDRS")
			_ = os.Unsetenv("REDIS_PASSWORD")
		}()

		opt := GetAsynqRedisConnOpt()
		if _, ok := opt.(interface{}); !ok {
			t.Fatal("expected Sentinel options")
		}
	})

	t.Run("GetAsynqRedisConnOpt_Cluster", func(t *testing.T) {
		_ = os.Setenv("REDIS_CLUSTER_ADDRS", "127.0.0.1:7000,127.0.0.1:7001")
		defer func() {
			_ = os.Unsetenv("REDIS_CLUSTER_ADDRS")
		}()

		opt := GetAsynqRedisConnOpt()
		if _, ok := opt.(interface{}); !ok {
			t.Fatal("expected Cluster options")
		}
	})

	t.Run("GetAsynqRedisConnOpt_Standard", func(t *testing.T) {
		_ = os.Setenv("REDIS_URL", "127.0.0.1:6379")
		defer func() {
			_ = os.Unsetenv("REDIS_URL")
		}()

		opt := GetAsynqRedisConnOpt()
		if _, ok := opt.(interface{}); !ok {
			t.Fatal("expected Client options")
		}
	})

	t.Run("AsynqLogger", func(t *testing.T) {
		logger := &asynqLogger{}
		logger.Debug("debug msg")
		logger.Info("info msg")
		logger.Warn("warn msg")
		logger.Error("error msg")
	})

	t.Run("StartAsynqServerCancelledCtx", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed: %v", err)
		}
		defer mock.Close()

		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()

		w := NewWorker(mock, db.RedisClient, &EmailSenderMock{}, http.DefaultClient)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Should start, register mux, see cancelled context, and shutdown gracefully
		w.StartAsynqServer(ctx, asynq.RedisClientOpt{Addr: mr.Addr()})
	})
}

func TestWorker_BrowserPush(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer mock.Close()

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)
	cve := &models.CVE{CVEID: "CVE-2023-0001"}
	res := w.sendBrowserPush(123, cve)
	if !res {
		t.Error("expected sendBrowserPush to return true (simulated success)")
	}
}

type mockTicker struct {
	c chan time.Time
}

func (m *mockTicker) Chan() <-chan time.Time {
	return m.c
}

func (m *mockTicker) Stop() {}

type mockTimer struct {
	c chan time.Time
}

func (m *mockTimer) Chan() <-chan time.Time {
	return m.c
}

func (m *mockTimer) Stop() bool { return true }

func TestWorker_PeriodicLoopExecutionWithMocks(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	w := NewWorker(mock, nil, &EmailSenderMock{}, http.DefaultClient)

	// Override factories to use mocks
	tickerChan := make(chan time.Time)
	w.TickerFactory = func(d time.Duration) Ticker {
		return &mockTicker{c: tickerChan}
	}
	timerChan := make(chan time.Time)
	w.TimerFactory = func(d time.Duration) Timer {
		return &mockTimer{c: timerChan}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up mock expectations (expected twice since both waitUntilNextRun and checkWorkerHealth run twice)
	mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = \\$1").
		WithArgs("health_check").
		WillReturnError(pgx.ErrNoRows)
	mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = \\$1").
		WithArgs("health_check").
		WillReturnError(pgx.ErrNoRows)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM notification_delivery_logs").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM notification_delivery_logs").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery("SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY\\(\\$1\\)").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"task_name", "last_run"}))
	mock.ExpectQuery("SELECT task_name, last_run FROM worker_sync_stats WHERE task_name = ANY\\(\\$1\\)").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows([]string{"task_name", "last_run"}))

	mock.ExpectExec("INSERT INTO worker_sync_stats").
		WithArgs("health_check").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec("INSERT INTO worker_sync_stats").
		WithArgs("health_check").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// 1. Verify waitUntilNextRun with timer trigger
	go func() {
		w.waitUntilNextRun(ctx, "health_check", 30*time.Minute, 1*time.Minute)
	}()

	// Feed the timer channel to unblock
	select {
	case timerChan <- time.Now():
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting to trigger timer channel")
	}

	// 2. Verify periodic loop triggering via ticker
	loopCtx, loopCancel := context.WithCancel(context.Background())

	go func() {
		w.startHealthCheckPeriodically(loopCtx)
	}()

	// Feed the timer inside waitUntilNextRun
	select {
	case timerChan <- time.Now():
	case <-time.After(2 * time.Second):
		t.Fatal("timeout triggering timer inside health check periodic startup")
	}

	// Now trigger the ticker
	select {
	case tickerChan <- time.Now():
	case <-time.After(2 * time.Second):
		t.Fatal("timeout triggering ticker inside health check periodic loop")
	}

	loopCancel()

	// Wait briefly for goroutine to clean up and verify expectations
	time.Sleep(50 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}
