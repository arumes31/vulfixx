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

var redisPing = func() error {
	_, err := RedisClient.Ping(context.Background()).Result()
	return err
}

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

		if clusterAddrsStr != "" {
			// Redis Cluster
			addrs := strings.Split(clusterAddrsStr, ",")
			var parsedAddrs []string
			for _, entry := range addrs {
				entry = strings.TrimSpace(entry)
				if strings.HasPrefix(entry, "redis://") || strings.HasPrefix(entry, "rediss://") {
					opt, err := redis.ParseURL(entry)
					if err == nil {
						parsedAddrs = append(parsedAddrs, opt.Addr)
						if opt.Password != "" {
							password = opt.Password
						}
					}
				} else {
					parsedAddrs = append(parsedAddrs, entry)
				}
			}
			RedisClient = redis.NewClusterClient(&redis.ClusterOptions{
				Addrs:    parsedAddrs,
				Password: password,
			})
		} else {
			// Single Node Redis
			url := os.Getenv("REDIS_URL")
			if url == "" {
				url = "localhost:6379"
			}
			if strings.HasPrefix(url, "redis://") || strings.HasPrefix(url, "rediss://") {
				opt, err := redis.ParseURL(url)
				if err == nil {
					if password != "" {
						opt.Password = password
					}
					RedisClient = redis.NewClient(opt)
				} else {
					RedisClient = redis.NewClient(&redis.Options{
						Addr:     url,
						Password: password,
					})
				}
			} else {
				RedisClient = redis.NewClient(&redis.Options{
					Addr:     url,
					Password: password,
				})
			}
		}
	}

	return redisPing()
}

func CloseRedis() {
	if RedisClient != nil {
		_ = RedisClient.Close()
	}
}

