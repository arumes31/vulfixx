package llm

import (
	"context"
	"errors"
	"testing"
)

func TestGoogleFailoverQuotaExceeded(t *testing.T) {
	oldIncr := googleFailoverRPDIncr
	defer func() { googleFailoverRPDIncr = oldIncr }()

	tests := []struct {
		name      string
		f         googleFailover
		setupIncr func()
		want      bool
	}{
		{
			name: "limit_zero_returns_false",
			f: googleFailover{
				defRPD: 0,
			},
			setupIncr: func() {
				googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
					t.Fatal("should not be called")
					return 0, nil
				}
			},
			want: false,
		},
		{
			name: "redis_error_returns_false",
			f: googleFailover{
				defRPD: 10,
			},
			setupIncr: func() {
				googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
					return 0, errors.New("redis error")
				}
			},
			want: false,
		},
		{
			name: "under_limit_returns_false",
			f: googleFailover{
				defRPD: 10,
			},
			setupIncr: func() {
				googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
					return 5, nil
				}
			},
			want: false,
		},
		{
			name: "exact_limit_returns_false",
			f: googleFailover{
				defRPD: 10,
			},
			setupIncr: func() {
				googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
					return 10, nil
				}
			},
			want: false,
		},
		{
			name: "over_limit_returns_true",
			f: googleFailover{
				defRPD: 10,
			},
			setupIncr: func() {
				googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
					return 11, nil
				}
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupIncr()
			got := googleFailoverQuotaExceeded(context.Background(), tc.f)
			if got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
