package db

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestInitDBMock(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectPing()
	if err := Pool.Ping(context.Background()); err != nil {
		t.Errorf("expected ping to succeed, got %v", err)
	}
}

func TestRedisMock(t *testing.T) {
	mr, err := SetupTestRedis()
	if err != nil {
		t.Fatalf("failed to setup miniredis: %v", err)
	}
	defer mr.Close()

	if err := RedisClient.Ping(context.Background()).Err(); err != nil {
		t.Errorf("expected redis ping to succeed, got %v", err)
	}
}

func TestMigrate(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	// Mock base schema execution (schemaSQL starts with CREATE TABLE IF NOT EXISTS users)
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
	
	// Expectations for each migration query in migrate()
	queries := []string{
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS enable_email",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS enable_webhook",
		"CREATE TABLE IF NOT EXISTS sync_state",
		"CREATE INDEX IF NOT EXISTS idx_cves_published_date",
		"CREATE INDEX IF NOT EXISTS idx_cves_cvss_score",
		"CREATE INDEX IF NOT EXISTS idx_cves_updated_date",
		"CREATE TABLE IF NOT EXISTS assets",
		"CREATE TABLE IF NOT EXISTS asset_keywords",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS vector_string",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS \"references\"",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_score",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS cwe_id",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS cwe_name",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS github_poc_count",
		"ALTER TABLE user_subscriptions ADD COLUMN IF NOT EXISTS filter_logic",
		"ALTER TABLE cves ADD COLUMN IF NOT EXISTS osint_data",
		"CREATE TABLE IF NOT EXISTS user_cve_notes",
	}

	for _, q := range queries {
		// Use regex match for just the beginning of each query
		mock.ExpectExec(q).WillReturnResult(pgxmock.NewResult("ALTER", 0))
	}

	err = migrate(context.Background())
	if err != nil {
		t.Errorf("migrate failed: %v", err)
	}
}

func TestMigrateError(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnError(fmt.Errorf("schema fail"))
	
	err = migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to execute base schema") {
		t.Errorf("expected schema error, got %v", err)
	}
}

func TestMigrateQueryError(t *testing.T) {
	mock, err := SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
	mock.ExpectExec("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin").WillReturnError(fmt.Errorf("query fail"))
	
	err = migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "migration 0 failed") {
		t.Errorf("expected migration error, got %v", err)
	}
}

func TestCloseDB(t *testing.T) {
	// Test nil pool
	Pool = nil
	CloseDB() // Should not panic

	// Test real pool
	_, _ = SetupTestDB()
	CloseDB()
}

func TestRedisErrors(t *testing.T) {
	t.Setenv("REDIS_URL", "invalid:port")
	err := InitRedis()
	if err == nil {
		t.Error("expected error for invalid redis url")
	}
	
	RedisClient = nil
	CloseRedis() // Should not panic
}
