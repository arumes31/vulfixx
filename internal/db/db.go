package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
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

	if err := migrateFunc(context.Background()); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

func migrate(ctx context.Context) error {
	log.Println("Database Migration: Executing Goose migrations...")

	sslMode := os.Getenv("DB_SSLMODE")
	if sslMode == "" {
		sslMode = "prefer"
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME"), sslMode)

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

func CloseDB() {
	if ReplicaPool != nil && ReplicaPool != Pool {
		ReplicaPool.Close()
	}
	if Pool != nil {
		Pool.Close()
	}
}
