package db

import (
	"context"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

type RedisProvider interface {
	redis.Cmdable
	Pipeline() redis.Pipeliner
	Close() error
}

var RedisClient RedisProvider

func InitRedis() error {
	password := os.Getenv("REDIS_PASSWORD")

	// 1. Redis Sentinel Support
	masterName := os.Getenv("REDIS_SENTINEL_MASTER")
	if masterName != "" {
		sentinelAddrsStr := os.Getenv("REDIS_SENTINEL_ADDRS")
		if sentinelAddrsStr == "" {
			sentinelAddrsStr = os.Getenv("REDIS_URL")
		}
		if sentinelAddrsStr == "" {
			sentinelAddrsStr = "localhost:26379"
		}
		sentinelAddrs := strings.Split(sentinelAddrsStr, ",")
		for i := range sentinelAddrs {
			sentinelAddrs[i] = strings.TrimSpace(sentinelAddrs[i])
		}

		RedisClient = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    masterName,
			SentinelAddrs: sentinelAddrs,
			Password:      password,
		})
	} else {
		// 2. Redis Cluster or Single Node Support
		clusterAddrsStr := os.Getenv("REDIS_CLUSTER_ADDRS")
		if clusterAddrsStr == "" {
			clusterAddrsStr = os.Getenv("REDIS_URL")
		}

		if strings.Contains(clusterAddrsStr, ",") {
			// Redis Cluster
			addrs := strings.Split(clusterAddrsStr, ",")
			for i := range addrs {
				addrs[i] = strings.TrimSpace(addrs[i])
			}
			RedisClient = redis.NewClusterClient(&redis.ClusterOptions{
				Addrs:    addrs,
				Password: password,
			})
		} else {
			// Single Node Redis
			url := os.Getenv("REDIS_URL")
			if url == "" {
				url = "localhost:6379"
			}
			RedisClient = redis.NewClient(&redis.Options{
				Addr:     url,
				Password: password,
			})
		}
	}

	_, err := RedisClient.Ping(context.Background()).Result()
	return err
}

func CloseRedis() {
	if RedisClient != nil {
		_ = RedisClient.Close()
	}
}
