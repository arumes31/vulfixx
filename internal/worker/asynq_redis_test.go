package worker

import (
	"os"
	"reflect"
	"testing"

	"github.com/hibiken/asynq"
)

func TestGetAsynqRedisConnOpt(t *testing.T) {
	// Helper to clear relevant env vars before each subtest
	clearEnv := func() {
		os.Unsetenv("REDIS_PASSWORD")
		os.Unsetenv("REDIS_URL")
		os.Unsetenv("REDIS_SENTINEL_MASTER")
		os.Unsetenv("REDIS_SENTINEL_ADDRS")
		os.Unsetenv("REDIS_CLUSTER_ADDRS")
	}

	tests := []struct {
		name     string
		env      map[string]string
		wantType reflect.Type
		verify   func(t *testing.T, opt asynq.RedisConnOpt)
	}{
		{
			name:     "Default settings",
			env:      map[string]string{},
			wantType: reflect.TypeOf(asynq.RedisClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				clientOpt := opt.(asynq.RedisClientOpt)
				if clientOpt.Addr != defaultRedisAddr {
					t.Errorf("expected addr %s, got %s", defaultRedisAddr, clientOpt.Addr)
				}
			},
		},
		{
			name: "Standalone with URL and Password",
			env: map[string]string{
				"REDIS_URL":      "redis:6379",
				"REDIS_PASSWORD": "pass",
			},
			wantType: reflect.TypeOf(asynq.RedisClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				clientOpt := opt.(asynq.RedisClientOpt)
				if clientOpt.Addr != "redis:6379" {
					t.Errorf("expected addr redis:6379, got %s", clientOpt.Addr)
				}
				if clientOpt.Password != "pass" {
					t.Errorf("expected password pass, got %s", clientOpt.Password)
				}
			},
		},
		{
			name: "Sentinel with explicit addrs",
			env: map[string]string{
				"REDIS_SENTINEL_MASTER": "mymaster",
				"REDIS_SENTINEL_ADDRS":  "s1:26379, s2:26379",
				"REDIS_PASSWORD":        "spass",
			},
			wantType: reflect.TypeOf(asynq.RedisFailoverClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				failoverOpt := opt.(asynq.RedisFailoverClientOpt)
				if failoverOpt.MasterName != "mymaster" {
					t.Errorf("expected master mymaster, got %s", failoverOpt.MasterName)
				}
				expectedAddrs := []string{"s1:26379", "s2:26379"}
				if !reflect.DeepEqual(failoverOpt.SentinelAddrs, expectedAddrs) {
					t.Errorf("expected addrs %v, got %v", expectedAddrs, failoverOpt.SentinelAddrs)
				}
				if failoverOpt.Password != "spass" {
					t.Errorf("expected password spass, got %s", failoverOpt.Password)
				}
			},
		},
		{
			name: "Sentinel fallback to REDIS_URL",
			env: map[string]string{
				"REDIS_SENTINEL_MASTER": "mymaster",
				"REDIS_URL":             "s3:26379",
			},
			wantType: reflect.TypeOf(asynq.RedisFailoverClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				failoverOpt := opt.(asynq.RedisFailoverClientOpt)
				expectedAddrs := []string{"s3:26379"}
				if !reflect.DeepEqual(failoverOpt.SentinelAddrs, expectedAddrs) {
					t.Errorf("expected addrs %v, got %v", expectedAddrs, failoverOpt.SentinelAddrs)
				}
			},
		},
		{
			name: "Sentinel default fallback",
			env: map[string]string{
				"REDIS_SENTINEL_MASTER": "mymaster",
			},
			wantType: reflect.TypeOf(asynq.RedisFailoverClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				failoverOpt := opt.(asynq.RedisFailoverClientOpt)
				expectedAddrs := []string{defaultRedisSentinelAddr}
				if !reflect.DeepEqual(failoverOpt.SentinelAddrs, expectedAddrs) {
					t.Errorf("expected addrs %v, got %v", expectedAddrs, failoverOpt.SentinelAddrs)
				}
			},
		},
		{
			name: "Cluster with explicit addrs",
			env: map[string]string{
				"REDIS_CLUSTER_ADDRS": "c1:6379, c2:6379",
				"REDIS_PASSWORD":      "cpass",
			},
			wantType: reflect.TypeOf(asynq.RedisClusterClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				clusterOpt := opt.(asynq.RedisClusterClientOpt)
				expectedAddrs := []string{"c1:6379", "c2:6379"}
				if !reflect.DeepEqual(clusterOpt.Addrs, expectedAddrs) {
					t.Errorf("expected addrs %v, got %v", expectedAddrs, clusterOpt.Addrs)
				}
				if clusterOpt.Password != "cpass" {
					t.Errorf("expected password cpass, got %s", clusterOpt.Password)
				}
			},
		},
		{
			name: "Cluster fallback to REDIS_URL",
			env: map[string]string{
				"REDIS_URL": "c3:6379, c4:6379",
			},
			wantType: reflect.TypeOf(asynq.RedisClusterClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				clusterOpt := opt.(asynq.RedisClusterClientOpt)
				expectedAddrs := []string{"c3:6379", "c4:6379"}
				if !reflect.DeepEqual(clusterOpt.Addrs, expectedAddrs) {
					t.Errorf("expected addrs %v, got %v", expectedAddrs, clusterOpt.Addrs)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv()
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got := GetAsynqRedisConnOpt()
			if reflect.TypeOf(got) != tt.wantType {
				t.Errorf("GetAsynqRedisConnOpt() = %T, want %v", got, tt.wantType)
			}
			if tt.verify != nil {
				tt.verify(t, got)
			}
		})
	}
}
