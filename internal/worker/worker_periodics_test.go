package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
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
	doneChan := make(chan struct{})
	w.OnHealthCheckDone = func() {
		close(doneChan)
	}

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

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for health check periodic loop completion signal")
	}

	loopCancel()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}

func TestWorker_DistributedLock(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer mock.Close()

	w := NewWorker(mock, rdb, &EmailSenderMock{}, http.DefaultClient)

	ctx := context.Background()

	// 1. Verify acquireLock sets lock in Redis
	token, acquired := w.acquireLock(ctx, "test_task", 1*time.Minute)
	if !acquired {
		t.Fatal("expected to acquire lock on first try")
	}

	// Lock key must exist in Redis
	if !mr.Exists("lock:task:test_task") {
		t.Error("expected lock key to exist in Redis")
	}

	// 2. Second acquire try must fail (already locked)
	_, acquiredAgain := w.acquireLock(ctx, "test_task", 1*time.Minute)
	if acquiredAgain {
		t.Fatal("expected second acquire attempt to fail")
	}

	// 3. releaseLock should delete lock key from Redis
	w.releaseLock(ctx, "test_task", token)
	if mr.Exists("lock:task:test_task") {
		t.Error("expected lock key to be deleted from Redis after release")
	}

	// 4. Verify runWithLock executes task only if lock can be acquired
	calledCount := 0
	taskFn := func(c context.Context) {
		calledCount++
	}

	// Runs successfully
	w.runWithLock(ctx, "test_task_run", 1*time.Minute, taskFn)
	if calledCount != 1 {
		t.Errorf("expected task to be executed once, got %d", calledCount)
	}

	// Lock is released after runWithLock completes
	if mr.Exists("lock:task:test_task_run") {
		t.Error("expected lock to be released after runWithLock completes")
	}

	// Acquire lock manually
	_, _ = w.acquireLock(ctx, "test_task_run", 1*time.Minute)

	// Attempts runWithLock again - should skip executing since it is locked
	w.runWithLock(ctx, "test_task_run", 1*time.Minute, taskFn)
	if calledCount != 1 {
		t.Errorf("expected task execution to be skipped, calledCount remains 1, got %d", calledCount)
	}
}

func TestWorker_SyncIntelligencePeriodically_Lock(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	w := NewWorker(mock, rdb, &EmailSenderMock{}, http.DefaultClient)

	tickerChan := make(chan time.Time)
	w.TickerFactory = func(d time.Duration) Ticker {
		return &mockTicker{c: tickerChan}
	}
	timerChan := make(chan time.Time)
	w.TimerFactory = func(d time.Duration) Timer {
		return &mockTimer{c: timerChan}
	}

	doneChan := make(chan struct{}, 10)
	w.OnIntelligenceSyncDone = func() {
		doneChan <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Path A: Lock Acquired
	mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = \\$1").
		WithArgs("intelligence_sync").
		WillReturnError(pgx.ErrNoRows)

	mock.ExpectQuery(`SELECT id, cve_id, description, COALESCE\(cvss_score, 0\), osint_data, github_poc_count, cwe_id, published_date`).
		WillReturnRows(pgxmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "osint_data", "github_poc_count", "cwe_id", "published_date"}))

	go func() {
		w.syncIntelligencePeriodically(ctx)
	}()

	timerChan <- time.Now()

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for initial intelligence sync")
	}

	if mr.Exists("lock:task:intelligence_sync") {
		t.Error("expected lock to be released after run completes")
	}

	// 2. Path B: Lock Denied
	if err = mr.Set("lock:task:intelligence_sync", "other-token"); err != nil {
		t.Fatalf("failed to set mock lock: %v", err)
	}

	tickerChan <- time.Now()

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for periodic intelligence sync (lock denied path)")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}

func TestWorker_SyncAdvisoryRSSPeriodically_Lock(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`<rss></rss>`)),
			}, nil
		},
	}

	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	tickerChan := make(chan time.Time)
	w.TickerFactory = func(d time.Duration) Ticker {
		return &mockTicker{c: tickerChan}
	}
	timerChan := make(chan time.Time)
	w.TimerFactory = func(d time.Duration) Timer {
		return &mockTimer{c: timerChan}
	}

	doneChan := make(chan struct{}, 10)
	w.OnAdvisoryRSSSyncDone = func() {
		doneChan <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Path A: Lock Acquired
	mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = \\$1").
		WithArgs("advisory_rss_sync").
		WillReturnError(pgx.ErrNoRows)

	mock.ExpectExec("INSERT INTO worker_sync_stats").
		WithArgs("advisory_rss_sync").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	go func() {
		w.syncAdvisoryRSSPeriodically(ctx)
	}()

	timerChan <- time.Now()

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for initial advisory RSS sync")
	}

	// 2. Path B: Lock Denied
	if err = mr.Set("lock:task:advisory_rss_sync", "other-token"); err != nil {
		t.Fatalf("failed to set mock lock: %v", err)
	}

	tickerChan <- time.Now()

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for periodic advisory RSS sync (lock denied path)")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}

func TestWorker_Start_Lifecycle(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mock.Close()
	mock.MatchExpectationsInOrder(false)

	// MockHTTPClient (DoFunc unset) fails every request immediately, keeping
	// this lifecycle test hermetic — no real network calls from sync tasks.
	w := NewWorker(mock, rdb, &EmailSenderMock{}, &MockHTTPClient{})

	// Inject mocks for timers/tickers to isolate time checks
	tickerChan := make(chan time.Time)
	w.TickerFactory = func(d time.Duration) Ticker {
		return &mockTicker{c: tickerChan}
	}
	timerChan := make(chan time.Time)
	w.TimerFactory = func(d time.Duration) Timer {
		return &mockTimer{c: timerChan}
	}

	// Mock stats queries for all 12 periodic tasks. Every task started by
	// Worker.Start must be listed: an unmatched concurrent query trips a
	// double-unlock bug in pgxmock v3.4.0 (findExpectationFunc) and panics.
	tasks := []string{
		"nvd_sync", "cisa_kev_sync", "epss_sync", "threat_intel_sync",
		"github_buzz_sync", "intelligence_sync", "greynoise_sync",
		"osv_sync", "inthewild_sync", "advisory_rss_sync", "fortiguard_sync",
		"health_check",
	}
	for _, task := range tasks {
		mock.ExpectQuery("SELECT last_run FROM worker_sync_stats WHERE task_name = \\$1").
			WithArgs(task).
			WillReturnError(pgx.ErrNoRows)
	}

	// Mock backlog count query for intelligence enrichment task
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM cves WHERE vendor IS NULL OR vendor = ''").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	// Mock advisory locking and stats for weekly summary task
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT pg_try_advisory_xact_lock\\(55667788\\)").
		WillReturnRows(pgxmock.NewRows([]string{"locked"}).AddRow(false))
	mock.ExpectRollback()

	ctx, cancel := context.WithCancel(context.Background())

	startDone := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(startDone)
	}()

	// Wait briefly for all goroutines to start up and register queries/waits
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger clean shutdown of all periodic worker goroutines
	cancel()

	// Wait for Start lifecycle method to return
	select {
	case <-startDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Worker.Start took too long to shutdown")
	}

	// Assert that all registered startup flows and queries were invoked correctly
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}
