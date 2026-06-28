package llm

import (
	"context"
	"errors"
	"testing"
)

func TestGoogleFailoverQuotaExceeded(t *testing.T) {
	ctx := context.Background()
	orig := googleFailoverRPDIncr
	defer func() { googleFailoverRPDIncr = orig }()

	tests := []struct {
		name      string
		limit     int
		mockIncr  func(context.Context, string) (int64, error)
		wantQuota bool
	}{
		{
			name:      "NoLimit",
			limit:     0,
			mockIncr:  func(context.Context, string) (int64, error) { return 0, nil },
			wantQuota: false,
		},
		{
			name:      "RedisError",
			limit:     10,
			mockIncr:  func(context.Context, string) (int64, error) { return 0, errors.New("redis error") },
			wantQuota: false,
		},
		{
			name:      "UnderLimit",
			limit:     10,
			mockIncr:  func(context.Context, string) (int64, error) { return 5, nil },
			wantQuota: false,
		},
		{
			name:      "OverLimit",
			limit:     10,
			mockIncr:  func(context.Context, string) (int64, error) { return 15, nil },
			wantQuota: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := googleFailover{defRPD: tt.limit}
			googleFailoverRPDIncr = tt.mockIncr

			got := googleFailoverQuotaExceeded(ctx, f)
			if got != tt.wantQuota {
				t.Errorf("googleFailoverQuotaExceeded() = %v, want %v", got, tt.wantQuota)
			}
		})
	}
}
