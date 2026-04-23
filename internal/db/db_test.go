package db

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestInitDB(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping integration test in CI")
	}

	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_USER", "cveuser")
	t.Setenv("DB_PASSWORD", "cvepass")
	t.Setenv("DB_NAME", "cvetracker")

	err := InitDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "timeout") {
			t.Skipf("skipping integration test: DB not available: %v", err)
		}
		t.Fatalf("Failed to init DB: %v", err)
	}

	err = Pool.Ping(context.Background())
	if err != nil {
		t.Errorf("Expected to ping db successfully, got error: %v", err)
	}

	CloseDB()
}

func TestInitDBWithInvalidDSN(t *testing.T) {
	t.Setenv("DB_HOST", "invalid_host")
	t.Setenv("DB_PORT", "abc")
	t.Setenv("DB_USER", "user")
	t.Setenv("DB_PASSWORD", "pass")
	t.Setenv("DB_NAME", "db")

	err := InitDB()
	if err == nil {
		t.Fatal("Expected error with invalid DSN (port abc), but got nil")
	}
	CloseDB()
}

func TestRedis(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping integration test in CI")
	}

	t.Setenv("REDIS_URL", "localhost:6379")

	err := InitRedis()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skipf("skipping integration test: Redis not available: %v", err)
		}
		t.Fatalf("Failed to init redis: %v", err)
	}

	err = RedisClient.Ping(context.Background()).Err()
	if err != nil {
		t.Errorf("Expected to ping redis successfully, got error: %v", err)
	}

	CloseRedis()
}

func TestRedisInvalid(t *testing.T) {
	t.Setenv("REDIS_URL", "invalid_host:1234")

	err := InitRedis()
	if err == nil {
		t.Log("Redis client creation usually doesn't fail until ping")
	}
	CloseRedis()
}
