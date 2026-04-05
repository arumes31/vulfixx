package db

import (
	"context"
	"os"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func InitRedis() error {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "localhost:6379"
	}
	RedisClient = redis.NewClient(&redis.Options{
		Addr: url,
	})

	_, err := RedisClient.Ping(context.Background()).Result()
	return err
}

func CloseRedis() {
	if RedisClient != nil {
		RedisClient.Close()
	}
}
