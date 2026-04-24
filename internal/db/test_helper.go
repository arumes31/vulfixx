package db

import (
	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

// SetupTestDB initializes a mock DB pool for testing.
func SetupTestDB() (pgxmock.PgxPoolIface, error) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		return nil, err
	}
	Pool = mock
	return mock, nil
}

// SetupTestRedis initializes a miniredis instance for testing.
func SetupTestRedis() (*miniredis.Miniredis, error) {
	mr, err := miniredis.Run()
	if err != nil {
		return nil, err
	}
	RedisClient = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	return mr, nil
}
