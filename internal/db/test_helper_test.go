package db

import (
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
)

func TestSetupHelpers(t *testing.T) {
	t.Run("SetupTestDB", func(t *testing.T) {
		oldPool := Pool
		t.Cleanup(func() { Pool = oldPool })
		mock, err := SetupTestDB()
		if err != nil {
			t.Errorf("SetupTestDB failed: %v", err)
		}
		if mock == nil || Pool != mock {
			t.Error("SetupTestDB did not set Pool correctly")
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
