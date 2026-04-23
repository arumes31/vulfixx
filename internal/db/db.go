package db

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func InitDB() error {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("unable to parse database URL: %w", err)
	}

	Pool, err = pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := migrate(context.Background()); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

func migrate(ctx context.Context) error {
	queries := []string{
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS enable_email BOOLEAN DEFAULT TRUE;",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS enable_webhook BOOLEAN DEFAULT TRUE;",
		`CREATE TABLE IF NOT EXISTS sync_state (
			key VARCHAR(100) PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,
		"CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves (published_date DESC);",
		"CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves (cvss_score);",
		"CREATE INDEX IF NOT EXISTS idx_cves_updated_date ON cves (updated_date DESC);",
	}

	for _, q := range queries {
		if _, err := Pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func CloseDB() {
	if Pool != nil {
		Pool.Close()
	}
}
