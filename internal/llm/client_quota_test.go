package llm

import (
	"context"
	"cve-tracker/internal/db"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestGoogleFailoverQuotaExceeded(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	db.RedisClient = redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Cleanup env vars
	defer os.Unsetenv("GEMINI_FAILOVER_35FLASH_RPD")

	ctx := context.Background()
	f := googleFailover{
		model:    "gemini-3.5-flash",
		rpmEnvs:  []string{"GEMINI_FAILOVER_35FLASH_RPM"},
		rpdEnvs:  []string{"GEMINI_FAILOVER_35FLASH_RPD"},
		redisKey: "gemini35flash_calls_today",
	}

	tests := []struct {
		name       string
		rpdEnv     string
		closeRedis bool
		setup      func()
		want       bool
	}{
		{
			name:   "NoLimit",
			rpdEnv: "0",
			want:   false,
		},
		{
			name:   "UnderLimit",
			rpdEnv: "10",
			want:   false,
		},
		{
			name:   "OverLimit",
			rpdEnv: "1",
			want:   true,
		},
		{
			name:       "RedisError",
			rpdEnv:     "10",
			closeRedis: true,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.closeRedis {
				mr.Close()
			}
			os.Setenv("GEMINI_FAILOVER_35FLASH_RPD", tt.rpdEnv)

			if got := googleFailoverQuotaExceeded(ctx, f); got != tt.want {
				t.Errorf("googleFailoverQuotaExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}
