package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v3"
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

func TestMigrate_SqlOpenerFailure(t *testing.T) {
	oldSqlOpener := sqlOpener
	sqlOpener = func(driverName, dataSourceName string) (*sql.DB, error) {
		return nil, fmt.Errorf("forced open error")
	}
	defer func() { sqlOpener = oldSqlOpener }()

	err := migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "forced open error") {
		t.Errorf("expected connection error, got: %v", err)
	}
}

func TestMigrate_GooseFailure(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	oldSqlOpener := sqlOpener
	sqlOpener = func(driverName, dataSourceName string) (*sql.DB, error) {
		return db, nil
	}
	defer func() { sqlOpener = oldSqlOpener }()

	oldGooseUp := gooseUp
	gooseUp = func(ctx context.Context, db *sql.DB, dir string) error {
		return fmt.Errorf("forced goose failure")
	}
	defer func() { gooseUp = oldGooseUp }()

	err = migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "goose migration failed") {
		t.Errorf("expected goose migration failure, got: %v", err)
	}
}

func TestMigrate_Success(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	oldSqlOpener := sqlOpener
	sqlOpener = func(driverName, dataSourceName string) (*sql.DB, error) {
		return db, nil
	}
	defer func() { sqlOpener = oldSqlOpener }()

	oldGooseUp := gooseUp
	gooseUp = func(ctx context.Context, db *sql.DB, dir string) error {
		return nil
	}
	defer func() { gooseUp = oldGooseUp }()

	err = migrate(context.Background())
	if err != nil {
		t.Errorf("expected successful migration, got error: %v", err)
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
			},
			shortRetry: true,
			wantErr:    false,
		},
		{
			name: "Success Path - Explicit SSLMode",
			envs: map[string]string{"DB_HOST": "localhost", "DB_SSLMODE": "disable"},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectPing()
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
			oldMigrateFunc := migrateFunc
			defer func() {
				poolCreator = oldCreator
				dbRetryCount = oldRetryCount
				dbRetryDelay = oldRetryDelay
				migrateFunc = oldMigrateFunc
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

			if tt.name == "Migration Failure" {
				migrateFunc = func(ctx context.Context) error {
					return fmt.Errorf("migration fail")
				}
			} else {
				migrateFunc = func(ctx context.Context) error {
					return nil
				}
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
	_, _ = poolCreator(ctx, cfg)
}

func TestSetupDBHelper(t *testing.T) {
	t.Run("SetupTestDB", func(t *testing.T) {
		mock, err := SetupTestDB()
		if err != nil {
			t.Errorf("SetupTestDB failed: %v", err)
		}
		if mock == nil || Pool != mock {
			t.Error("SetupTestDB did not set Pool correctly")
		}
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
}

func TestInitDB_Replica(t *testing.T) {
	t.Run("Replica Configuration set", func(t *testing.T) {
		oldPool := Pool
		oldReplicaPool := ReplicaPool
		defer func() {
			Pool = oldPool
			ReplicaPool = oldReplicaPool
		}()

		t.Setenv("DB_HOST", "localhost")
		t.Setenv("DB_PORT", "5432")
		t.Setenv("DB_USER", "user")
		t.Setenv("DB_PASSWORD", "pass")
		t.Setenv("DB_NAME", "db")
		t.Setenv("DB_SSLMODE", "disable")

		t.Setenv("DB_REPLICA_HOST", "localhost")
		t.Setenv("DB_REPLICA_PORT", "5432")
		t.Setenv("DB_REPLICA_USER", "user")
		t.Setenv("DB_REPLICA_PASSWORD", "pass")
		t.Setenv("DB_REPLICA_NAME", "db_replica")

		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()

		mock.ExpectPing()

		oldCreator := poolCreator
		poolCreator = func(ctx context.Context, config *pgxpool.Config) (DBPool, error) {
			return mock, nil
		}
		defer func() { poolCreator = oldCreator }()

		oldMigrateFunc := migrateFunc
		migrateFunc = func(ctx context.Context) error {
			return nil
		}
		defer func() { migrateFunc = oldMigrateFunc }()

		err = InitDB()
		if err != nil {
			t.Errorf("expected InitDB to succeed, got %v", err)
		}
		if ReplicaPool == nil {
			t.Error("expected ReplicaPool to be initialized")
		}
	})
}
