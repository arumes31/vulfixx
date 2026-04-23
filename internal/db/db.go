package db

import (
	"context"
	"fmt"
	"os"
	"time"

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

	// Wait for database to be ready
	var pingErr error
	for i := 0; i < 15; i++ {
		pingErr = Pool.Ping(context.Background())
		if pingErr == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if pingErr != nil {
		return fmt.Errorf("database connection failed after retries: %w", pingErr)
	}

	if err := migrate(context.Background()); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

func migrate(ctx context.Context) error {
	// First ensure base schema is present
	if _, err := Pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("failed to execute base schema: %w", err)
	}

	// Then run incremental migrations
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
		`CREATE TABLE IF NOT EXISTS assets (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(100),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS asset_keywords (
			id SERIAL PRIMARY KEY,
			asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
			keyword VARCHAR(255) NOT NULL,
			UNIQUE(asset_id, keyword)
		);`,
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
