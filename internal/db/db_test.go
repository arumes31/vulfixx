package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestInitDBMock(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectPing()
	if err := Pool.Ping(context.Background()); err != nil {
		t.Errorf("expected ping to succeed, got %v", err)
	}
}

func TestRedisMock(t *testing.T) {
	mr, err := SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	if err := RedisClient.Ping(context.Background()).Err(); err != nil {
		t.Errorf("expected redis ping to succeed, got %v", err)
	}
}

func TestMigrate(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	// Mock base schema execution
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
	
	// Expectations for each migration query in migrate()
	queries := []string{
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS enable_email",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS enable_webhook",
		"CREATE TABLE IF NOT EXISTS sync_state",
		"CREATE INDEX IF NOT EXISTS idx_cves_published_date",
		"CREATE INDEX IF NOT EXISTS idx_cves_cvss_score",
		"CREATE INDEX IF NOT EXISTS idx_cves_updated_date",
		"CREATE TABLE IF NOT EXISTS assets",
		"CREATE TABLE IF NOT EXISTS asset_keywords",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS vector_string",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS \"references\"",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_score",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS cwe_id",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS cwe_name",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS github_poc_count",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS filter_logic",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS osint_data",
		"CREATE TABLE IF NOT EXISTS user_cve_notes",
	}

	for _, q := range queries {
		mock.ExpectExec(q).WillReturnResult(pgxmock.NewResult("ALTER", 0))
	}

	err = migrate(context.Background())
	if err != nil {
		t.Errorf("migrate failed: %v", err)
	}
}

func TestMigrateError(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnError(fmt.Errorf("schema fail"))
	
	err = migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to execute base schema") {
		t.Errorf("expected schema error, got %v", err)
	}
}

func TestMigrateQueryError(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
	mock.ExpectExec("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin").WillReturnError(fmt.Errorf("query fail"))
	
	err = migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "migration 0 failed") {
		t.Errorf("expected migration error, got %v", err)
	}
}

func TestCloseDB(t *testing.T) {
	// Test nil pool
	Pool = nil
	CloseDB() // Should not panic

	// Test real pool
	_, _ = SetupTestDB()
	CloseDB()
}

func TestInitRedisTable(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "Valid Redis URL",
			url:     mr.Addr(),
			wantErr: false,
		},
		{
			name:    "Invalid Redis URL",
			url:     "invalid-host:1234",
			wantErr: true,
		},
		{
			name:    "Empty URL (defaults to localhost:6379)",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.url != "" {
				t.Setenv("REDIS_URL", tt.url)
			} else {
				os.Unsetenv("REDIS_URL")
			}

			err := InitRedis()
			if (err != nil) != tt.wantErr {
				t.Errorf("InitRedis() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCloseRedis(t *testing.T) {
	t.Run("Nil Client", func(t *testing.T) {
		RedisClient = nil
		CloseRedis() // should not panic
	})

	t.Run("Valid Client", func(t *testing.T) {
		mr, _ := miniredis.Run()
		defer mr.Close()
		RedisClient = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		CloseRedis()
	})
}

func TestInitDB_Complex(t *testing.T) {
	tests := []struct {
		name        string
		envs        map[string]string
		mockSetup   func(mock pgxmock.PgxPoolIface)
		creatorFail bool
		shortRetry  bool
		wantErr     bool
		errContains string
	}{
		{
			name: "Success Path - Default SSLMode and Ping Retry",
			envs: map[string]string{"DB_HOST": "localhost"}, // DB_SSLMODE not set
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectPing().WillReturnError(fmt.Errorf("not ready yet"))
				mock.ExpectPing().WillReturnError(fmt.Errorf("not ready yet"))
				mock.ExpectPing() // Succeeds on 3rd try
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
				for i := 0; i < 18; i++ {
					mock.ExpectExec("").WillReturnResult(pgxmock.NewResult("ALTER", 0))
				}
			},
			shortRetry: true,
			wantErr:    false,
		},
		{
			name: "Success Path - Explicit SSLMode",
			envs: map[string]string{"DB_HOST": "localhost", "DB_SSLMODE": "disable"},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectPing()
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
				for i := 0; i < 18; i++ {
					mock.ExpectExec("").WillReturnResult(pgxmock.NewResult("ALTER", 0))
				}
			},
			wantErr: false,
		},
		{
			name: "ParseConfig Error",
			envs: map[string]string{"DB_SSLMODE": "invalid"},
			wantErr:     true,
			errContains: "unable to parse database URL",
		},
		{
			name: "Pool Creator Error",
			envs: map[string]string{"DB_HOST": "localhost"},
			creatorFail: true,
			wantErr:     true,
			errContains: "unable to create connection pool",
		},
		{
			name: "Ping Failure",
			envs: map[string]string{"DB_HOST": "localhost"},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectPing().WillReturnError(fmt.Errorf("ping fail"))
				mock.ExpectPing().WillReturnError(fmt.Errorf("ping fail"))
			},
			shortRetry:  true,
			wantErr:     true,
			errContains: "database connection failed after retries",
		},
		{
			name: "Migration Failure",
			envs: map[string]string{"DB_HOST": "localhost"},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectPing()
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnError(fmt.Errorf("migration fail"))
			},
			wantErr:     true,
			errContains: "migration failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore globals
			oldCreator := poolCreator
			oldRetryCount := dbRetryCount
			oldRetryDelay := dbRetryDelay
			defer func() {
				poolCreator = oldCreator
				dbRetryCount = oldRetryCount
				dbRetryDelay = oldRetryDelay
			}()

			if tt.name == "Success Path - Default SSLMode and Ping Retry" {
				os.Unsetenv("DB_SSLMODE")
				dbRetryCount = 5
				dbRetryDelay = 1 * time.Millisecond
			} else if tt.shortRetry {
				dbRetryCount = 2
				dbRetryDelay = 1 * time.Millisecond
			} else {
				dbRetryCount = 1
				dbRetryDelay = 1 * time.Millisecond
			}

			mock, _ := pgxmock.NewPool()
			if tt.mockSetup != nil {
				tt.mockSetup(mock)
			}

			poolCreator = func(ctx context.Context, config *pgxpool.Config) (DBPool, error) {
				if tt.creatorFail {
					return nil, fmt.Errorf("creator fail")
				}
				return mock, nil
			}

			// Set envs with valid defaults
			t.Setenv("DB_HOST", "localhost")
			t.Setenv("DB_PORT", "5432")
			t.Setenv("DB_USER", "user")
			t.Setenv("DB_PASSWORD", "pass")
			t.Setenv("DB_NAME", "db")
			t.Setenv("DB_SSLMODE", "disable")

			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			// Special case to trigger ParseConfig error
			if tt.name == "ParseConfig Error" {
				// Using a malformed port that strconv.ParseUint will fail on
				// pgx key-value parser is very lenient, but some values are validated
				t.Setenv("DB_PORT", "65536") // Port out of range
			}

			err := InitDB()
			if (err != nil) != tt.wantErr {
				t.Errorf("InitDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("InitDB() error = %v, wantErr contains %v", err, tt.errContains)
			}
		})
	}
}

func TestSetupHelpers(t *testing.T) {
	t.Run("SetupTestDB", func(t *testing.T) {
		mock, err := SetupTestDB()
		if err != nil {
			t.Errorf("SetupTestDB failed: %v", err)
		}
		if mock == nil || Pool != mock {
			t.Error("SetupTestDB did not set Pool correctly")
		}
	})

	t.Run("SetupTestRedis", func(t *testing.T) {
		mr, err := SetupTestRedis()
		if err != nil {
			t.Errorf("SetupTestRedis failed: %v", err)
		}
		if mr == nil || RedisClient == nil {
			t.Error("SetupTestRedis did not set RedisClient correctly")
		}
		mr.Close()
	})
}
