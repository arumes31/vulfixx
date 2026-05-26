package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"
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
	gooseUp = func(ctx context.Context, db *sql.DB, dir string) error {
		return goose.UpContext(ctx, db, dir)
	}
)

//go:embed sql/migrations/*.sql
var embedMigrations embed.FS

func migrate(ctx context.Context) error {
	log.Println("Database Migration: Executing Goose migrations...")

	sslMode := os.Getenv("DB_SSLMODE")
	if sslMode == "" {
		sslMode = "prefer"
	}
	hostPort := os.Getenv("DB_HOST")
	if port := os.Getenv("DB_PORT"); port != "" {
		hostPort = net.JoinHostPort(hostPort, port)
	}
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD")),
		Host:     hostPort,
		Path:     "/" + os.Getenv("DB_NAME"),
		RawQuery: "sslmode=" + url.QueryEscape(sslMode),
	}
	dsn := u.String()

	dbConn, err := sqlOpener("pgx", dsn)
	if err != nil {
		return fmt.Errorf("unable to open database connection for goose: %w", err)
	}
	defer dbConn.Close()

	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("goose set dialect failed: %w", err)
	}

	if err := gooseUp(ctx, dbConn, "sql/migrations"); err != nil {
		return fmt.Errorf("goose migration failed: %w", err)
	}

	log.Println("Database Migration: Embedded Goose migrations completed successfully.")
	return nil
}
