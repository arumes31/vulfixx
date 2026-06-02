package web

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v3"
)

func TestStartStatsTicker(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	t.Run("InitialRefreshAndTicker_DBPath", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.Redis = nil // Force DB path
		app.StatsInterval = 100 * time.Millisecond

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Expectations for initial refresh
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\).*COUNT\\(\\*\\) FILTER.*updated_date.*COUNT\\(\\*\\) FILTER.*cisa_kev.*COUNT\\(\\*\\) FILTER.*cvss_score").
			WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(10, 2, 3, 1, 1, 2, 3, 4, 1, 1, 1, 1))
		mock.ExpectQuery("SELECT cwe_id, COALESCE\\(MAX\\(cwe_name\\), 'Unknown'\\), COUNT\\(\\*\\) as cnt").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 5))

		// Expectations for second refresh (ticker)
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\).*COUNT\\(\\*\\) FILTER.*updated_date.*COUNT\\(\\*\\) FILTER.*cisa_kev.*COUNT\\(\\*\\) FILTER.*cvss_score").
			WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(11, 3, 4, 2, 2, 3, 4, 2, 2, 2, 2, 2))
		mock.ExpectQuery("SELECT cwe_id, COALESCE\\(MAX\\(cwe_name\\), 'Unknown'\\), COUNT\\(\\*\\) as cnt").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-89", "SQLi", 6))

		go app.StartStatsTicker(ctx)

		// Wait for initial refresh and exactly one ticker tick (hopefully)
		time.Sleep(150 * time.Millisecond)
		cancel()

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}

		statsCache.RLock()
		defer statsCache.RUnlock()
		if statsCache.total != 11 {
			t.Errorf("expected total 11, got %d", statsCache.total)
		}
	})

	t.Run("RedisCacheHit", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.StatsInterval = 1 * time.Hour // Don't tick

		stats := GlobalCVEStatsJSON{
			Total:       500,
			LastUpdated: time.Now(),
		}
		data, _ := json.Marshal(stats)
		_ = app.Redis.Set(context.Background(), "vulfixx:dashboard_stats", string(data), 0).Err()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go app.StartStatsTicker(ctx)
		time.Sleep(50 * time.Millisecond)
		cancel()

		statsCache.RLock()
		defer statsCache.RUnlock()
		if statsCache.total != 500 {
			t.Errorf("expected total 500 from Redis, got %d", statsCache.total)
		}
	})

	t.Run("RedisCacheMiss_DBRefresh_RedisSave", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.StatsInterval = 1 * time.Hour // Don't tick

		// Ensure Redis is empty
		app.Redis.Del(context.Background(), "vulfixx:dashboard_stats")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// DB Expectations
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\).*COUNT\\(\\*\\) FILTER.*updated_date.*COUNT\\(\\*\\) FILTER.*cisa_kev.*COUNT\\(\\*\\) FILTER.*cvss_score").
			WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(100, 10, 5, 2, 2, 8, 30, 60, 40, 30, 20, 10))
		mock.ExpectQuery("SELECT cwe_id, COALESCE\\(MAX\\(cwe_name\\), 'Unknown'\\), COUNT\\(\\*\\) as cnt").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 20))

		go app.StartStatsTicker(ctx)
		time.Sleep(100 * time.Millisecond) // Give it time to refresh and save to Redis
		cancel()

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}

		// Verify Redis population
		val, err := app.Redis.Get(context.Background(), "vulfixx:dashboard_stats").Result()
		if err != nil {
			t.Errorf("expected stats in Redis, got error: %v", err)
		}
		var stats GlobalCVEStatsJSON
		if err := json.Unmarshal([]byte(val), &stats); err != nil {
			t.Errorf("failed to unmarshal Redis stats: %v", err)
		}
		if stats.Total != 100 {
			t.Errorf("expected total 100 in Redis, got %d", stats.Total)
		}
	})
}

func TestStopStatsTicker(t *testing.T) {
	statsMu.Lock()
	originalCancel := cancelStats
	called := false
	cancelStats = func() {
		called = true
	}
	statsMu.Unlock()

	t.Cleanup(func() {
		statsMu.Lock()
		cancelStats = originalCancel
		statsMu.Unlock()
	})

	StopStatsTicker()

	if !called {
		t.Error("expected cancelStats to be called")
	}
	if cancelStats != nil {
		t.Error("expected cancelStats to be nil after StopStatsTicker")
	}

	// Calling it again should be safe
	StopStatsTicker()
}

func TestStartStatsTicker_Shutdown(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	app := setupTestApp(t, mock)
	app.Redis = nil
	app.StatsInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	// Initial refresh expectations
	mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\)").
		WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectQuery("SELECT cwe_id").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}))

	done := make(chan struct{})
	go func() {
		app.StartStatsTicker(ctx)
		close(done)
	}()

	// Wait for initial refresh
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("StartStatsTicker did not shut down after context cancellation")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestInitTemplates_TickerLogic(t *testing.T) {
	// We need to bypass the flag check to test the ticker start logic
	// But InitTemplates uses flag.Lookup("test.v")
	// We can't easily change that, but we can verify that when it's NOT test mode,
	// it would start the ticker. Since we ARE in test mode, we've already covered
	// the early return.

	mock, _ := db.SetupTestDB()
	app := setupTestApp(t, mock)

	// Ensure we are clean
	StopStatsTicker()

	app.InitTemplates()

	statsMu.Lock()
	cancel := cancelStats
	statsMu.Unlock()

	if cancel != nil {
		t.Error("expected cancelStats to be nil because flag.Lookup('test.v') is not nil in tests")
	}
}
