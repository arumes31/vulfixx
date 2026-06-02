package worker

import (
	"reflect"
	"testing"

	"github.com/hibiken/asynq"
)

func TestGetAsynqRedisConnOpt(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantType reflect.Type
		verify   func(t *testing.T, opt asynq.RedisConnOpt)
	}{
		{
			name: "Sentinel with ADDRS",
			env: map[string]string{
				"REDIS_SENTINEL_MASTER": "mymaster",
				"REDIS_SENTINEL_ADDRS":  "127.0.0.1:26379,127.0.0.1:26380",
				"REDIS_PASSWORD":        "secret",
			},
			wantType: reflect.TypeOf(asynq.RedisFailoverClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisFailoverClientOpt)
				if o.MasterName != "mymaster" {
					t.Errorf("got MasterName %s, want mymaster", o.MasterName)
				}
				wantAddrs := []string{"127.0.0.1:26379", "127.0.0.1:26380"}
				if !reflect.DeepEqual(o.SentinelAddrs, wantAddrs) {
					t.Errorf("got SentinelAddrs %v, want %v", o.SentinelAddrs, wantAddrs)
				}
				if o.Password != "secret" {
					t.Errorf("got Password %s, want secret", o.Password)
				}
			},
		},
		{
			name: "Sentinel with REDIS_URL",
			env: map[string]string{
				"REDIS_SENTINEL_MASTER": "mymaster",
				"REDIS_URL":             "127.0.0.1:26379",
				"REDIS_SENTINEL_ADDRS":  "",
			},
			wantType: reflect.TypeOf(asynq.RedisFailoverClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisFailoverClientOpt)
				wantAddrs := []string{"127.0.0.1:26379"}
				if !reflect.DeepEqual(o.SentinelAddrs, wantAddrs) {
					t.Errorf("got SentinelAddrs %v, want %v", o.SentinelAddrs, wantAddrs)
				}
			},
		},
		{
			name: "Sentinel Default Fallback",
			env: map[string]string{
				"REDIS_SENTINEL_MASTER": "mymaster",
				"REDIS_URL":             "",
				"REDIS_SENTINEL_ADDRS":  "",
			},
			wantType: reflect.TypeOf(asynq.RedisFailoverClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisFailoverClientOpt)
				wantAddrs := []string{defaultRedisSentinelAddr}
				if !reflect.DeepEqual(o.SentinelAddrs, wantAddrs) {
					t.Errorf("got SentinelAddrs %v, want %v", o.SentinelAddrs, wantAddrs)
				}
			},
		},
		{
			name: "Cluster with CLUSTER_ADDRS",
			env: map[string]string{
				"REDIS_CLUSTER_ADDRS": "127.0.0.1:7000,127.0.0.1:7001",
				"REDIS_PASSWORD":      "clustersecret",
			},
			wantType: reflect.TypeOf(asynq.RedisClusterClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisClusterClientOpt)
				wantAddrs := []string{"127.0.0.1:7000", "127.0.0.1:7001"}
				if !reflect.DeepEqual(o.Addrs, wantAddrs) {
					t.Errorf("got Addrs %v, want %v", o.Addrs, wantAddrs)
				}
				if o.Password != "clustersecret" {
					t.Errorf("got Password %s, want clustersecret", o.Password)
				}
			},
		},
		{
			name: "Cluster with comma in REDIS_URL",
			env: map[string]string{
				"REDIS_URL": "127.0.0.1:7000,127.0.0.1:7001",
			},
			wantType: reflect.TypeOf(asynq.RedisClusterClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisClusterClientOpt)
				wantAddrs := []string{"127.0.0.1:7000", "127.0.0.1:7001"}
				if !reflect.DeepEqual(o.Addrs, wantAddrs) {
					t.Errorf("got Addrs %v, want %v", o.Addrs, wantAddrs)
				}
			},
		},
		{
			name: "Standard with REDIS_URL",
			env: map[string]string{
				"REDIS_URL":      "127.0.0.1:6379",
				"REDIS_PASSWORD": "pass",
			},
			wantType: reflect.TypeOf(asynq.RedisClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisClientOpt)
				if o.Addr != "127.0.0.1:6379" {
					t.Errorf("got Addr %s, want 127.0.0.1:6379", o.Addr)
				}
				if o.Password != "pass" {
					t.Errorf("got Password %s, want pass", o.Password)
				}
			},
		},
		{
			name: "Standard Default Fallback",
			env: map[string]string{
				"REDIS_URL": "",
			},
			wantType: reflect.TypeOf(asynq.RedisClientOpt{}),
			verify: func(t *testing.T, opt asynq.RedisConnOpt) {
				o := opt.(asynq.RedisClientOpt)
				if o.Addr != defaultRedisAddr {
					t.Errorf("got Addr %s, want %s", o.Addr, defaultRedisAddr)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear relevant env vars
			vars := []string{"REDIS_PASSWORD", "REDIS_SENTINEL_MASTER", "REDIS_SENTINEL_ADDRS", "REDIS_CLUSTER_ADDRS", "REDIS_URL"}
			for _, v := range vars {
				t.Setenv(v, "")
			}

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got := GetAsynqRedisConnOpt()
			if reflect.TypeOf(got) != tt.wantType {
				t.Errorf("GetAsynqRedisConnOpt() type = %v, want %v", reflect.TypeOf(got), tt.wantType)
			}
			tt.verify(t, got)
		})
	}
}
