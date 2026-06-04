package web

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"errors"
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

		// Wait for initial refresh and exactly one ticker tick
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

	t.Run("RedisGetError", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.StatsInterval = 1 * time.Hour

		// Mock Redis error (miniredis doesn't easily mock errors on Get, but we can just not set anything and it returns Nil, which is handled).
		// Wait, the code handles err == nil && val != "". If Get returns error, it falls through.
		// To trigger the DB path when Redis is present but failing:
		// Actually miniredis returns Nil if key doesn't exist.

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Expect DB path
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\)").WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(10, 2, 3, 1, 1, 2, 3, 4, 1, 1, 1, 1))
		mock.ExpectQuery("SELECT cwe_id").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}))

		go app.StartStatsTicker(ctx)
		time.Sleep(50 * time.Millisecond)
		cancel()

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("RedisUnmarshalError", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.StatsInterval = 1 * time.Hour

		// Set invalid JSON in Redis
		_ = app.Redis.Set(context.Background(), "vulfixx:dashboard_stats", "invalid-json", 0).Err()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Expect DB path
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\)").WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(20, 2, 3, 1, 1, 2, 3, 4, 1, 1, 1, 1))
		mock.ExpectQuery("SELECT cwe_id").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}))

		go app.StartStatsTicker(ctx)
		time.Sleep(50 * time.Millisecond)
		cancel()

		statsCache.RLock()
		defer statsCache.RUnlock()
		if statsCache.total != 20 {
			t.Errorf("expected total 20 after Redis unmarshal error, got %d", statsCache.total)
		}
	})

	t.Run("DBQueryError_CWE", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.StatsInterval = 1 * time.Hour
		app.Redis = nil

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Success on main stats
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\)").WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(30, 2, 3, 1, 1, 2, 3, 4, 1, 1, 1, 1))
		// Error on CWE query
		mock.ExpectQuery("SELECT cwe_id").WillReturnError(errors.New("db error"))

		go app.StartStatsTicker(ctx)
		time.Sleep(50 * time.Millisecond)
		cancel()

		statsCache.RLock()
		defer statsCache.RUnlock()
		if statsCache.total != 30 {
			t.Errorf("expected total 30 even if CWE query fails, got %d", statsCache.total)
		}
	})

	t.Run("DBScanError_CWE", func(t *testing.T) {
		app := setupTestApp(t, mock)
		app.StatsInterval = 1 * time.Hour
		app.Redis = nil

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Success on main stats
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\)").WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit", "scrit", "shigh", "smed", "slow", "e1", "e2", "e3", "e4"}).AddRow(40, 2, 3, 1, 1, 2, 3, 4, 1, 1, 1, 1))
		// Scan error on CWE query (e.g. column count mismatch or wrong type)
		mock.ExpectQuery("SELECT cwe_id").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-1", "Name", "not-an-int"))

		go app.StartStatsTicker(ctx)
		time.Sleep(50 * time.Millisecond)
		cancel()

		statsCache.RLock()
		defer statsCache.RUnlock()
		if statsCache.total != 40 {
			t.Errorf("expected total 40 even if CWE scan fails, got %d", statsCache.total)
		}
	})
}

func TestStopStatsTicker(t *testing.T) {
	t.Run("StopWhileNil", func(t *testing.T) {
		statsMu.Lock()
		cancelStats = nil
		statsMu.Unlock()

		// Should not panic
		StopStatsTicker()
	})

	t.Run("StopWhileRunning", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		statsMu.Lock()
		cancelStats = cancel
		statsMu.Unlock()

		StopStatsTicker()

		// Verify context is cancelled
		select {
		case <-ctx.Done():
			// OK
		case <-time.After(100 * time.Millisecond):
			t.Errorf("context was not cancelled by StopStatsTicker")
		}

		statsMu.Lock()
		if cancelStats != nil {
			t.Errorf("cancelStats should be nil after StopStatsTicker")
		}
		statsMu.Unlock()
	})
}
