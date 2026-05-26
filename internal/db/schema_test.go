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

	err = migrate(context.Background())
	if err != nil {
		t.Errorf("expected successful migration, got error: %v", err)
	}
}
