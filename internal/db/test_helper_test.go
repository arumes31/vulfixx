package db

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestSetupHelpers(t *testing.T) {
	ctx := context.Background()

	t.Run("SetupTestDB", func(t *testing.T) {
		oldPool := Pool
		oldReplicaPool := ReplicaPool
		t.Cleanup(func() {
			Pool = oldPool
			ReplicaPool = oldReplicaPool
		})
		mock, err := SetupTestDB()
		if err != nil {
			t.Errorf("SetupTestDB failed: %v", err)
		}
		if mock == nil || Pool != mock {
			t.Error("SetupTestDB did not set Pool correctly")
		}
		if ReplicaPool != mock {
			t.Error("SetupTestDB did not set ReplicaPool correctly")
		}

		// Functional Verification
		mock.ExpectPing()
		if err := Pool.Ping(ctx); err != nil {
			t.Errorf("expected pool ping to succeed, got %v", err)
		}

		mock.ExpectQuery("SELECT 1").WillReturnRows(pgxmock.NewRows([]string{"one"}).AddRow(1))
		var val int
		if err := ReplicaPool.QueryRow(ctx, "SELECT 1").Scan(&val); err != nil {
			t.Errorf("expected replica pool query to succeed, got %v", err)
		}
		if val != 1 {
			t.Errorf("expected 1, got %d", val)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("SetupTestRedis", func(t *testing.T) {
		oldRedisClient := RedisClient
		t.Cleanup(func() { RedisClient = oldRedisClient })
		mr, err := SetupTestRedis()
		if err != nil {
			t.Fatalf("SetupTestRedis failed: %v", err)
		}
		t.Cleanup(func() { mr.Close() })
		if mr == nil || RedisClient == nil {
			t.Error("SetupTestRedis did not set RedisClient correctly")
		} else if client, ok := RedisClient.(*redis.Client); ok {
			if client.Options().Addr != mr.Addr() {
				t.Errorf("SetupTestRedis did not set correct address: expected %s, got %s", mr.Addr(), client.Options().Addr)
			}

			// Functional Verification
			if err := RedisClient.Ping(ctx).Err(); err != nil {
				t.Errorf("expected redis ping to succeed, got %v", err)
			}

			if err := RedisClient.Set(ctx, "test_key", "test_value", 0).Err(); err != nil {
				t.Errorf("expected redis set to succeed, got %v", err)
			}

			val, err := RedisClient.Get(ctx, "test_key").Result()
			if err != nil {
				t.Errorf("expected redis get to succeed, got %v", err)
			}
			if val != "test_value" {
				t.Errorf("expected test_value, got %s", val)
			}
		} else {
			t.Error("RedisClient is not *redis.Client")
		}
	})

	t.Run("SetupTestDB Error", func(t *testing.T) {
		oldFuncDB := newPoolCall
		newPoolCall = func() (pgxmock.PgxPoolIface, error) {
			return nil, fmt.Errorf("forced error")
		}
		defer func() { newPoolCall = oldFuncDB }()

		_, err := SetupTestDB()
		if err == nil {
			t.Error("expected error but got nil")
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
