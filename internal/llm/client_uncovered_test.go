package llm

import (
	"context"
	"errors"
	"testing"
)

func TestGoogleFailoverQuotaExceeded(t *testing.T) {
	tests := []struct {
		name        string
		limit       int
		count       int64
		incrErr     error
		expected    bool
	}{
		{
			name:     "No limit set (<= 0)",
			limit:    0,
			count:    0,
			incrErr:  nil,
			expected: false,
		},
		{
			name:     "Increment returns error",
			limit:    100,
			count:    0,
			incrErr:  errors.New("redis error"),
			expected: false,
		},
		{
			name:     "Quota not reached",
			limit:    100,
			count:    50,
			incrErr:  nil,
			expected: false,
		},
		{
			name:     "Quota reached exactly",
			limit:    100,
			count:    100,
			incrErr:  nil,
			expected: false, // > check, so 100 > 100 is false
		},
		{
			name:     "Quota exceeded",
			limit:    100,
			count:    101,
			incrErr:  nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the original and restore it after
			originalIncr := googleFailoverRPDIncr
			defer func() { googleFailoverRPDIncr = originalIncr }()

			googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
				return tt.count, tt.incrErr
			}

			// We need a googleFailover with a fake defRPD.
			f := googleFailover{
				model:    "test-model",
				defRPD:   tt.limit,
				redisKey: "test-key",
			}

			// Run the function under test
			actual := googleFailoverQuotaExceeded(context.Background(), f)

			if actual != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, actual)
			}
		})
	}
}
