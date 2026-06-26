package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

var (
	migrateFunc = migrate
	sqlOpener   = func(driverName, dataSourceName string) (*sql.DB, error) {
		return sql.Open(driverName, dataSourceName)
	}
	gooseSetDialect = func(dialect string) error {
		return goose.SetDialect(dialect)
	}
	gooseUp = func(ctx context.Context, db *sql.DB, dir string) error {
		return goose.UpContext(ctx, db, dir)
	}
)

//go:embed sql/migrations/*.sql
var embedMigrations embed.FS

func migrate(ctx context.Context) error {
	slog.Info("Database Migration: Checking and executing Goose migrations...")

	sslMode := os.Getenv("DB_SSLMODE")
	if sslMode == "" {
		sslMode = "prefer"
	}
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	hostPort := dbHost
	if dbPort != "" {
		hostPort = net.JoinHostPort(hostPort, dbPort)
	}
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD")),
		Host:     hostPort,
		Path:     "/" + dbName,
		RawQuery: "sslmode=" + url.QueryEscape(sslMode),
	}
	dsn := u.String()

	dbConn, err := sqlOpener("pgx", dsn)
	if err != nil {
		slog.Error("Database Migration: Unable to open database connection for goose", "error", err, "host", dbHost, "db", dbName)
		return fmt.Errorf("unable to open database connection for goose: %w", err)
	}
	defer dbConn.Close()

	goose.SetBaseFS(embedMigrations)
	if err := gooseSetDialect("postgres"); err != nil {
		slog.Error("Database Migration: Goose set dialect failed", "error", err)
		return fmt.Errorf("goose set dialect failed: %w", err)
	}

	if err := gooseUp(ctx, dbConn, "sql/migrations"); err != nil {
		slog.Error("Database Migration: Migration execution failed", "error", err)
		return fmt.Errorf("goose migration failed: %w", err)
	}

	slog.Info("Database Migration: Embedded migrations completed successfully.", "db", dbName)
	return nil
}
