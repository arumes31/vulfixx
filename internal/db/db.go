package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBPool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
	Close()
	Ping(ctx context.Context) error
}

var (
	Pool         DBPool
	dbRetryCount = 15
	dbRetryDelay = 1 * time.Second
	poolCreator  = func(ctx context.Context, config *pgxpool.Config) (DBPool, error) {
		return pgxpool.NewWithConfig(ctx, config)
	}
)

func InitDB() error {
	sslMode := os.Getenv("DB_SSLMODE")
	if sslMode == "" {
		sslMode = "prefer"
	}
	if sslMode == "disable" {
		log.Println("WARNING: DB_SSLMODE is set to 'disable'. Database traffic is unencrypted.")
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), sslMode)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("unable to parse database URL: %w", err)
	}

	Pool, err = poolCreator(context.Background(), poolConfig)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %w", err)
	}

	// Wait for database to be ready
	var pingErr error
	for i := 0; i < dbRetryCount; i++ {
		pingErr = Pool.Ping(context.Background())
		if pingErr == nil {
			break
		}
		time.Sleep(dbRetryDelay)
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
		"CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves (published_date DESC);",
		"CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves (cvss_score);",
		"CREATE INDEX IF NOT EXISTS idx_cves_updated_date ON cves (updated_date DESC);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS vector_string TEXT;",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS \"references\" TEXT[];",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_score NUMERIC(6,5);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(50);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS cwe_name TEXT;",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS github_poc_count INTEGER DEFAULT 0;",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS filter_logic TEXT DEFAULT '';",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS osint_data JSONB DEFAULT '{}';",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS product VARCHAR(255);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS affected_products JSONB DEFAULT '[]';",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS osv_data JSONB DEFAULT '{}';",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_hits INTEGER DEFAULT 0;",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_classification VARCHAR(50);",
		"CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor);",
		"CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);",
		"CREATE INDEX IF NOT EXISTS idx_cves_affected_products ON cves USING GIN (affected_products);",
	}

	for i, q := range queries {
		if _, err := Pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("migration %d failed executing query %q: %w", i, q, err)
		}
	}
	return nil
}

func CloseDB() {
	if Pool != nil {
		Pool.Close()
	}
}
