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
	ReplicaPool  DBPool
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

	// Set connection pool configuration limits
	poolConfig.MaxConns = 25
	poolConfig.MinConns = 5
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 15 * time.Minute

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

	// Setup database read-replica (Item 11)
	replicaHost := os.Getenv("DB_REPLICA_HOST")
	if replicaHost != "" {
		replicaPort := os.Getenv("DB_REPLICA_PORT")
		if replicaPort == "" {
			replicaPort = os.Getenv("DB_PORT")
		}
		replicaUser := os.Getenv("DB_REPLICA_USER")
		if replicaUser == "" {
			replicaUser = os.Getenv("DB_USER")
		}
		replicaPassword := os.Getenv("DB_REPLICA_PASSWORD")
		if replicaPassword == "" {
			replicaPassword = os.Getenv("DB_PASSWORD")
		}
		replicaName := os.Getenv("DB_REPLICA_NAME")
		if replicaName == "" {
			replicaName = os.Getenv("DB_NAME")
		}

		replicaDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			replicaHost, replicaPort, replicaUser, replicaPassword, replicaName, sslMode)

		replicaConfig, err := pgxpool.ParseConfig(replicaDSN)
		if err != nil {
			log.Printf("WARNING: unable to parse database replica URL: %v. Falling back to primary pool.", err)
			ReplicaPool = Pool
		} else {
			replicaConfig.MaxConns = 15
			replicaConfig.MinConns = 3
			replicaConfig.MaxConnLifetime = 30 * time.Minute
			replicaConfig.MaxConnIdleTime = 15 * time.Minute

			ReplicaPool, err = poolCreator(context.Background(), replicaConfig)
			if err != nil {
				log.Printf("WARNING: unable to create database replica pool: %v. Falling back to primary pool.", err)
				ReplicaPool = Pool
			} else {
				log.Println("Database read-replica connection pool initialized successfully.")
			}
		}
	} else {
		log.Println("DB_REPLICA_HOST not set. Routing read queries to primary database pool.")
		ReplicaPool = Pool
	}

	if err := migrate(context.Background()); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

func migrate(ctx context.Context) error {
	// Item 12: Range Partitioning migration for existing databases
	var cvesTableExists bool
	err := Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'cves')").Scan(&cvesTableExists)
	if err != nil {
		return fmt.Errorf("failed to check if cves table exists: %w", err)
	}

	if cvesTableExists {
		var isPartitioned bool
		err = Pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_partitioned_table
				WHERE partrelid = 'cves'::regclass
			)
		`).Scan(&isPartitioned)
		if err != nil {
			isPartitioned = false
		}

		if !isPartitioned {
			log.Println("Database Migration: Migrating 'cves' table to native range-partitioned structure by published_date...")

			// 1. Drop foreign keys on dependent tables (to allow renaming / changing cves)
			dropFKs := []string{
				"ALTER TABLE notification_delivery_logs DROP CONSTRAINT IF EXISTS notification_delivery_logs_cve_id_fkey",
				"ALTER TABLE user_cve_status DROP CONSTRAINT IF EXISTS user_cve_status_cve_id_fkey",
				"ALTER TABLE cve_notes DROP CONSTRAINT IF EXISTS cve_notes_cve_id_fkey",
				"ALTER TABLE cve_notes DROP CONSTRAINT IF EXISTS user_cve_notes_cve_id_fkey",
				"ALTER TABLE alert_history DROP CONSTRAINT IF EXISTS alert_history_cve_id_fkey",
			}
			for _, q := range dropFKs {
				if _, err := Pool.Exec(ctx, q); err != nil {
					log.Printf("WARNING: failed to drop constraint: %v", err)
				}
			}

			// 2. Rename existing cves table
			if _, err := Pool.Exec(ctx, "ALTER TABLE cves RENAME TO cves_old"); err != nil {
				return fmt.Errorf("failed to rename cves table to cves_old: %w", err)
			}

			// 3. Execute base schema to create partitioned cves table and its partitions
			if _, err := Pool.Exec(ctx, schemaSQL); err != nil {
				return fmt.Errorf("failed to execute base schema for partitioning: %w", err)
			}

			// 4. Copy data from cves_old to partitioned cves, defaulting null published_date to current time
			copySQL := `
				INSERT INTO cves (
					id, cve_id, description, cvss_score, vector_string, cisa_kev, exploit_available,
					epss_score, cwe_id, cwe_name, github_poc_count, greynoise_hits, greynoise_classification,
					greynoise_last_updated, osv_data, osv_last_updated, inthewild_data, inthewild_last_updated,
					osint_data, published_date, updated_date, "references", configurations, vendor, product,
					affected_products, darknet_mentions, darknet_last_seen, priority, created_at, updated_at
				)
				SELECT 
					id, cve_id, description, cvss_score, vector_string, cisa_kev, exploit_available,
					epss_score, cwe_id, cwe_name, github_poc_count, greynoise_hits, greynoise_classification,
					greynoise_last_updated, osv_data, osv_last_updated, inthewild_data, inthewild_last_updated,
					osint_data, COALESCE(published_date, CURRENT_TIMESTAMP), updated_date, "references", configurations, vendor, product,
					affected_products, darknet_mentions, darknet_last_seen, priority, created_at, updated_at
				FROM cves_old
			`
			if _, err := Pool.Exec(ctx, copySQL); err != nil {
				_, _ = Pool.Exec(ctx, "ALTER TABLE cves_old RENAME TO cves")
				return fmt.Errorf("failed to copy CVE data to partitioned table: %w", err)
			}

			// 5. Update SERIAL sequence value for the partitioned table
			seqSQL := "SELECT setval(pg_get_serial_sequence('cves', 'id'), COALESCE(max(id), 1)) FROM cves"
			if _, err := Pool.Exec(ctx, seqSQL); err != nil {
				log.Printf("WARNING: failed to align SERIAL sequence for cves table: %v", err)
			}

			// 6. Drop the old table
			if _, err := Pool.Exec(ctx, "DROP TABLE cves_old CASCADE"); err != nil {
				log.Printf("WARNING: failed to drop cves_old: %v", err)
			}

			log.Println("Database Migration: 'cves' table range-partitioning migration completed successfully.")
		}
	} else {
		// Table doesn't exist, just execute base schema SQL directly
		if _, err := Pool.Exec(ctx, schemaSQL); err != nil {
			return fmt.Errorf("failed to execute base schema: %w", err)
		}
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
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS osv_last_updated TIMESTAMP WITH TIME ZONE;",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_hits INTEGER DEFAULT 0;",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_classification VARCHAR(50);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_last_updated TIMESTAMP WITH TIME ZONE;",
		"CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor);",
		"CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);",
		"CREATE INDEX IF NOT EXISTS idx_cves_affected_products ON cves USING GIN (affected_products jsonb_path_ops);",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;",
		"CREATE INDEX IF NOT EXISTS idx_user_activity_logs_user_type_created ON user_activity_logs (user_id, activity_type, created_at DESC);",
	}

	for i, q := range queries {
		if _, err := Pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("migration %d failed executing query %q: %w", i, q, err)
		}
	}
	return nil
}

func CloseDB() {
	if ReplicaPool != nil && ReplicaPool != Pool {
		ReplicaPool.Close()
	}
	if Pool != nil {
		Pool.Close()
	}
}
