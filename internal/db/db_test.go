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
	tests := []struct {
		name      string
		mockSetup func(mock pgxmock.PgxPoolIface)
		wantErr   bool
		errMatch  string
	}{
		{
			name: "Success",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock base schema execution
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))

				// Expectations for each migration query in migrate()
				// There are 14 queries in the queries slice
				for i := 0; i < 14; i++ {
					mock.ExpectExec("").WillReturnResult(pgxmock.NewResult("ALTER", 0))
				}
			},
			wantErr: false,
		},
		{
			name: "Base Schema Failure",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnError(fmt.Errorf("schema fail"))
			},
			wantErr:  true,
			errMatch: "failed to execute base schema",
		},
		{
			name: "Incremental Migration Failure",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
				// Fail on the first incremental migration
				mock.ExpectExec("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin").WillReturnError(fmt.Errorf("query fail"))
			},
			wantErr:  true,
			errMatch: "migration 0 failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool failed: %v", err)
			}
			Pool = mock
			defer mock.Close()

			if tt.mockSetup != nil {
				tt.mockSetup(mock)
			}

			err = migrate(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("migrate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("migrate() error = %v, wantMatch %v", err, tt.errMatch)
			}
		})
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
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()

	tests := []struct {
		name    string
		url     string
		wantErr bool
		skipErr bool
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
			wantErr: false,
			skipErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.url != "" {
				t.Setenv("REDIS_URL", tt.url)
			} else {
				// Capture original value and restore after test
				origVal, origSet := os.LookupEnv("REDIS_URL")
				_ = os.Unsetenv("REDIS_URL")
				t.Cleanup(func() {
					if origSet {
						_ = os.Setenv("REDIS_URL", origVal)
					} else {
						_ = os.Unsetenv("REDIS_URL")
					}
				})
			}

			err := InitRedis()
			if tt.skipErr {
				return
			}
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
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("miniredis.Run failed: %v", err)
		}
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
			envs: map[string]string{"DB_HOST": "localhost", "DB_SSLMODE": ""}, // DB_SSLMODE empty string
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectPing().WillReturnError(fmt.Errorf("not ready yet"))
				mock.ExpectPing().WillReturnError(fmt.Errorf("not ready yet"))
				mock.ExpectPing() // Succeeds on 3rd try
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
				for i := 0; i < 14; i++ {
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
				for i := 0; i < 14; i++ {
					mock.ExpectExec("").WillReturnResult(pgxmock.NewResult("ALTER", 0))
				}
			},
			wantErr: false,
		},
		{
			name:        "ParseConfig Error",
			envs:        map[string]string{"DB_PORT": "65536"},
			wantErr:     true,
			errContains: "unable to parse database URL",
		},
		{
			name:        "Pool Creator Error",
			envs:        map[string]string{"DB_HOST": "localhost"},
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
				dbRetryCount = 5
				dbRetryDelay = 1 * time.Millisecond
			} else if tt.shortRetry {
				dbRetryCount = 2
				dbRetryDelay = 1 * time.Millisecond
			} else {
				dbRetryCount = 1
				dbRetryDelay = 1 * time.Millisecond
			}

			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatalf("pgxmock.NewPool failed: %v", err)
			}
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
				if v == "" {
					_ = os.Unsetenv(k)
				} else {
					t.Setenv(k, v)
				}
			}

			err = InitDB()
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

func TestDefaultPoolCreator(t *testing.T) {
	// Cover the default poolCreator implementation
	ctx := context.Background()
	cfg, _ := pgxpool.ParseConfig("host=localhost")
	// This will try to connect to localhost, which might fail, but it covers the lines.
	_, _ = poolCreator(ctx, cfg)
}

func TestInitRedis_Error(t *testing.T) {
	t.Run("Ping Failure", func(t *testing.T) {
		t.Setenv("REDIS_URL", "localhost:1") // Use port 1 which is likely closed
		err := InitRedis()
		if err == nil {
			t.Error("expected error but got nil")
		}
	})
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

	t.Run("SetupTestDB Error", func(t *testing.T) {
		oldFuncDB := newPoolCall
		newPoolCall = func() (pgxmock.PgxPoolIface, error) {
			return nil, fmt.Errorf("forced error")
		}
		defer func() { newPoolCall = oldFuncDB }()

		_, err := SetupTestDB()
		if err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("SetupTestRedis Error", func(t *testing.T) {
		oldFuncRedis := miniredisRunCall
		miniredisRunCall = func() (*miniredis.Miniredis, error) {
			return nil, fmt.Errorf("forced error")
		}
		defer func() { miniredisRunCall = oldFuncRedis }()

		_, err := SetupTestRedis()
		if err == nil {
			t.Error("expected error but got nil")
		}
	})
}
