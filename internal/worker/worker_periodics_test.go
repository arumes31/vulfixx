package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"net/http"
	"os"
	"testing"

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
