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
	_, err := Pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to execute base schema: %w", err)
	}

	_, err = Pool.Exec(ctx, "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;")
	return err
}

func CloseDB() {
	if Pool != nil {
		Pool.Close()
	}
}
