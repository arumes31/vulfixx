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
			WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit"}).AddRow(10, 2, 3, 1))
		mock.ExpectQuery("SELECT.*COUNT\\(\\*\\) FILTER.*FROM cves").WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low"}).AddRow(1, 2, 3, 4))
		mock.ExpectQuery("SELECT cwe_id, COALESCE\\(MAX\\(cwe_name\\), 'Unknown'\\), COUNT\\(\\*\\) as cnt").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-79", "XSS", 5))
		mock.ExpectQuery("SELECT.*COUNT\\(\\*\\) FILTER.*FROM cves").WillReturnRows(pgxmock.NewRows([]string{"e1", "e2", "e3", "e4"}).AddRow(1, 1, 1, 1))

		// Expectations for second refresh (ticker)
		mock.ExpectQuery("(?i)SELECT.*COUNT\\(\\*\\).*COUNT\\(\\*\\) FILTER.*updated_date.*COUNT\\(\\*\\) FILTER.*cisa_kev.*COUNT\\(\\*\\) FILTER.*cvss_score").
			WillReturnRows(pgxmock.NewRows([]string{"total", "new24h", "kev", "crit"}).AddRow(11, 3, 4, 2))
		mock.ExpectQuery("SELECT.*COUNT\\(\\*\\) FILTER.*FROM cves").WillReturnRows(pgxmock.NewRows([]string{"crit", "high", "med", "low"}).AddRow(2, 3, 4, 2))
		mock.ExpectQuery("SELECT cwe_id, COALESCE\\(MAX\\(cwe_name\\), 'Unknown'\\), COUNT\\(\\*\\) as cnt").WillReturnRows(pgxmock.NewRows([]string{"cwe_id", "cwe_name", "cnt"}).AddRow("CWE-89", "SQLi", 6))
		mock.ExpectQuery("SELECT.*COUNT\\(\\*\\) FILTER.*FROM cves").WillReturnRows(pgxmock.NewRows([]string{"e1", "e2", "e3", "e4"}).AddRow(2, 2, 2, 2))

		go app.StartStatsTicker(ctx)

		// Wait for initial refresh and exactly one ticker tick (hopefully)
		// Using a slightly longer sleep to ensure the second tick is processed,
		// but matching the expectations carefully.
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
			Total: 500,
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
}
