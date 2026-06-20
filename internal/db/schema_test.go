package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

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

	// Test with various environment configurations to ensure full coverage of DSN construction
	tests := []struct {
		name string
		envs map[string]string
	}{
		{
			name: "Default SSLMode and No Port",
			envs: map[string]string{
				"DB_SSLMODE":  "",
				"DB_HOST":     "localhost",
				"DB_PORT":     "",
				"DB_USER":     "user",
				"DB_PASSWORD": "pass",
				"DB_NAME":     "db",
			},
		},
		{
			name: "Explicit SSLMode and Port",
			envs: map[string]string{
				"DB_SSLMODE":  "disable",
				"DB_HOST":     "localhost",
				"DB_PORT":     "5432",
				"DB_USER":     "user",
				"DB_PASSWORD": "pass",
				"DB_NAME":     "db",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envs {
				if v == "" {
					t.Setenv(k, "")
				} else {
					t.Setenv(k, v)
				}
			}
			err = migrate(context.Background())
			if err != nil {
				t.Errorf("expected successful migration for %s, got error: %v", tt.name, err)
			}
		})
	}
}

func TestDefaultSchemaWrappers(t *testing.T) {
	// Call default wrappers to ensure they are at least executed for coverage
	// Using a real driver name but invalid DSN for sqlOpener
	db, _ := sqlOpener("pgx", "")
	if db != nil {
		db.Close()
	}

	_ = gooseSetDialect("invalid")

	// gooseUp will likely return error with nil db, which is fine
	_ = gooseUp(context.Background(), nil, "invalid")
}

func TestMigrate_GooseSetDialectFailure(t *testing.T) {
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

	oldGooseSetDialect := gooseSetDialect
	gooseSetDialect = func(dialect string) error {
		return fmt.Errorf("forced set dialect failure")
	}
	defer func() { gooseSetDialect = oldGooseSetDialect }()

	err = migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "forced set dialect failure") {
		t.Errorf("expected goose set dialect failure, got: %v", err)
	}
}
