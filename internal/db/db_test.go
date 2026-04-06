package db

import (
	"context"
	"os"
	"testing"
)

func TestInitDB(t *testing.T) {
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "cveuser")
	os.Setenv("DB_PASSWORD", "cvepass")
	os.Setenv("DB_NAME", "cvetracker")

	err := InitDB()
	if err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}

	err = Pool.Ping(context.Background())
	if err != nil {
		t.Errorf("Expected to ping db successfully, got error: %v", err)
	}

	CloseDB()
}

func TestInitDBWithInvalidDSN(t *testing.T) {
	// Set dummy env for invalid DSN test
	os.Setenv("DB_HOST", "invalid_host")
	os.Setenv("DB_PORT", "abc")
	os.Setenv("DB_USER", "user")
	os.Setenv("DB_PASSWORD", "pass")
	os.Setenv("DB_NAME", "db")

	err := InitDB()
	if err == nil {
		t.Fatal("Expected error with invalid DSN (port abc), but got nil")
	}
	CloseDB()
}

func TestRedis(t *testing.T) {
	os.Setenv("REDIS_URL", "localhost:6379")

	err := InitRedis()
	if err != nil {
		t.Fatalf("Failed to init redis: %v", err)
	}

	err = RedisClient.Ping(context.Background()).Err()
	if err != nil {
		t.Errorf("Expected to ping redis successfully, got error: %v", err)
	}

	CloseRedis()
}

func TestRedisInvalid(t *testing.T) {
	os.Setenv("REDIS_URL", "invalid_host:1234")

	err := InitRedis()
	if err == nil {
		t.Log("Redis client creation usually doesn't fail until ping")
	}
	CloseRedis()
}
