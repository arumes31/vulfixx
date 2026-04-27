package db

import (
	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

var (
	newPoolCall      = func() (pgxmock.PgxPoolIface, error) { return pgxmock.NewPool() }
	miniredisRunCall = func() (*miniredis.Miniredis, error) { return miniredis.Run() }
)

// SetupTestDB initializes a mock DB pool for testing.
func SetupTestDB() (pgxmock.PgxPoolIface, error) {
	mock, err := newPoolCall()
	if err != nil {
		return nil, err
	}
	Pool = mock
	return mock, nil
}

// SetupTestRedis initializes a miniredis instance for testing.
func SetupTestRedis() (*miniredis.Miniredis, error) {
	mr, err := miniredisRunCall()
	if err != nil {
		return nil, err
	}
	RedisClient = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	return mr, nil
}
