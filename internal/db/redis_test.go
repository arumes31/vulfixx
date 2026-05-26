package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

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

func TestInitRedisTable(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()

	tests := []struct {
		name    string
		url     string
		wantErr bool
		skipErr bool
	}{
		{
			name:    "Valid Redis URL",
			url:     mr.Addr(),
			wantErr: false,
		},
		{
			name:    "Invalid Redis URL",
			url:     "invalid-host:1234",
			wantErr: true,
		},
		{
			name:    "Empty URL (defaults to localhost:6379)",
			url:     "",
			wantErr: false,
			skipErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.url != "" {
				t.Setenv("REDIS_URL", tt.url)
			} else {
				// Capture original value and restore after test
				origVal, origSet := os.LookupEnv("REDIS_URL")
				_ = os.Unsetenv("REDIS_URL")
				t.Cleanup(func() {
					if origSet {
						_ = os.Setenv("REDIS_URL", origVal)
					} else {
						_ = os.Unsetenv("REDIS_URL")
					}
				})
			}

			err := InitRedis()
			if tt.skipErr {
				return
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("InitRedis() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCloseRedis(t *testing.T) {
	t.Run("Nil Client", func(t *testing.T) {
		orig := RedisClient
		t.Cleanup(func() { RedisClient = orig })
		RedisClient = nil
		CloseRedis() // should not panic
	})

	t.Run("Valid Client", func(t *testing.T) {
		orig := RedisClient
		t.Cleanup(func() { RedisClient = orig })
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("miniredis.Run failed: %v", err)
		}
		t.Cleanup(func() { mr.Close() })
		RedisClient = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		CloseRedis()
	})
}

func TestInitRedis_Error(t *testing.T) {
	t.Run("Ping Failure", func(t *testing.T) {
		t.Setenv("REDIS_URL", "localhost:1") // Use port 1 which is likely closed
		err := InitRedis()
		if err == nil {
			t.Error("expected error but got nil")
		}
	})
}

func TestSetupRedisHelper(t *testing.T) {
	t.Run("SetupTestRedis", func(t *testing.T) {
		orig := RedisClient
		t.Cleanup(func() { RedisClient = orig })
		mr, err := SetupTestRedis()
		if err != nil {
			t.Fatalf("SetupTestRedis failed: %v", err)
		}
		t.Cleanup(func() { mr.Close() })
		if mr == nil || RedisClient == nil {
			t.Error("SetupTestRedis did not set RedisClient correctly")
		}
	})

	t.Run("SetupTestRedis Error", func(t *testing.T) {
		oldFuncRedis := miniredisRunCall
		miniredisRunCall = func() (*miniredis.Miniredis, error) {
			return nil, fmt.Errorf("forced error")
		}
		defer func() { miniredisRunCall = oldFuncRedis }()

		_, err := SetupTestRedis()
		if err == nil {
			t.Error("expected error but got nil")
		}
	})
}

func TestInitRedis_SentinelAndCluster(t *testing.T) {
	// Mock redisPing globally and restore it
	oldPing := redisPing
	redisPing = func() error {
		return fmt.Errorf("forced offline error")
	}
	defer func() { redisPing = oldPing }()

	t.Run("Sentinel Configuration fail ping", func(t *testing.T) {
		t.Setenv("REDIS_SENTINEL_MASTER", "mymaster")
		t.Setenv("REDIS_SENTINEL_ADDRS", "127.0.0.1:26379, 127.0.0.1:26380")
		t.Setenv("REDIS_URL", "")

		err := InitRedis()
		if err == nil || !strings.Contains(err.Error(), "forced offline error") {
			t.Errorf("expected forced offline error, got %v", err)
		}
	})

	t.Run("Sentinel Default Address fail ping", func(t *testing.T) {
		t.Setenv("REDIS_SENTINEL_MASTER", "mymaster")
		t.Setenv("REDIS_SENTINEL_ADDRS", "")
		t.Setenv("REDIS_URL", "")

		err := InitRedis()
		if err == nil || !strings.Contains(err.Error(), "forced offline error") {
			t.Errorf("expected forced offline error, got %v", err)
		}
	})

	t.Run("Cluster Configuration fail ping", func(t *testing.T) {
		t.Setenv("REDIS_SENTINEL_MASTER", "")
		t.Setenv("REDIS_CLUSTER_ADDRS", "127.0.0.1:7000,127.0.0.1:7001")
		t.Setenv("REDIS_URL", "")

		err := InitRedis()
		if err == nil || !strings.Contains(err.Error(), "forced offline error") {
			t.Errorf("expected forced offline error, got %v", err)
		}
	})
}

func TestInitRedis_Cluster_URL(t *testing.T) {
	oldPing := redisPing
	redisPing = func() error { return nil }
	defer func() { redisPing = oldPing }()

	t.Run("Cluster with redis:// URL", func(t *testing.T) {
		t.Setenv("REDIS_CLUSTER_ADDRS", "redis://:pass@localhost:6379, localhost:6380")
		err := InitRedis()
		if err != nil {
			t.Errorf("InitRedis failed: %v", err)
		}
	})

	t.Run("Cluster with rediss:// URL", func(t *testing.T) {
		t.Setenv("REDIS_CLUSTER_ADDRS", "rediss://localhost:6379")
		err := InitRedis()
		if err != nil {
			t.Errorf("InitRedis failed: %v", err)
		}
	})
}

func TestInitRedis_Single_URL(t *testing.T) {
	oldPing := redisPing
	redisPing = func() error { return nil }
	defer func() { redisPing = oldPing }()

	t.Run("Single with redis:// URL", func(t *testing.T) {
		t.Setenv("REDIS_URL", "redis://:pass@localhost:6379")
		err := InitRedis()
		if err != nil {
			t.Errorf("InitRedis failed: %v", err)
		}
	})

	t.Run("Single with rediss:// URL", func(t *testing.T) {
		t.Setenv("REDIS_URL", "rediss://localhost:6379")
		err := InitRedis()
		if err != nil {
			t.Errorf("InitRedis failed: %v", err)
		}
	})
}

func TestInitRedis_Sentinel_URL(t *testing.T) {
	oldPing := redisPing
	redisPing = func() error { return nil }
	defer func() { redisPing = oldPing }()

	t.Run("Sentinel with REDIS_URL fallback", func(t *testing.T) {
		t.Setenv("REDIS_SENTINEL_MASTER", "mymaster")
		t.Setenv("REDIS_SENTINEL_ADDRS", "")
		t.Setenv("REDIS_URL", "localhost:26379,localhost:26380")
		err := InitRedis()
		if err != nil {
			t.Errorf("InitRedis failed: %v", err)
		}
	})
}

func TestInitRedis_ParseError(t *testing.T) {
	oldPing := redisPing
	redisPing = func() error { return nil }
	defer func() { redisPing = oldPing }()

	t.Run("Single Node Parse Error fallback", func(t *testing.T) {
		t.Setenv("REDIS_URL", "redis://invalid-url:path")
		err := InitRedis()
		// It should fallback to default addr if parse fails
		if err != nil {
			t.Errorf("InitRedis should not have failed: %v", err)
		}
	})

	t.Run("Cluster Parse Error skip", func(t *testing.T) {
		t.Setenv("REDIS_CLUSTER_ADDRS", "redis://invalid-url:path, localhost:6380")
		err := InitRedis()
		if err != nil {
			t.Errorf("InitRedis should not have failed: %v", err)
		}
	})
}
