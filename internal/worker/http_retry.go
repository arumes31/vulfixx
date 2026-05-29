package worker

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// RetryConfig defines the configuration for the DoWithRetry helper.
type RetryConfig struct {
	MaxRetries  int
	MaxWait     time.Duration
	ShouldRetry func(resp *http.Response, err error, attempt int) (bool, time.Duration)
	Label       string
}

// DefaultShouldRetry is a standard implementation of ShouldRetry that handles 429 Too Many Requests.
func DefaultShouldRetry(resp *http.Response, err error, attempt int) (bool, time.Duration) {
	if err != nil {
		return false, 0
	}
	if resp == nil {
		return false, 0
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		waitTime := 5 * time.Second
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, errSec := strconv.Atoi(ra); errSec == nil {
				waitTime = time.Duration(seconds) * time.Second
			}
		}
		return true, waitTime
	}
	return false, 0
}

// DoWithRetry executes an HTTP request with retry logic based on the provided configuration.
func DoWithRetry(ctx context.Context, client HTTPClient, config RetryConfig, reqFunc func() (*http.Request, error)) (*http.Response, error) {
	var lastResp *http.Response
	var lastErr error

	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := reqFunc()
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)

		shouldRetry, waitTime := config.ShouldRetry(resp, err, attempt)
		if !shouldRetry {
			return resp, err
		}

		// We are going to retry, so close the current response body if it exists
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}

		lastResp = resp
		lastErr = err

		if config.MaxWait > 0 && waitTime > config.MaxWait {
			waitTime = config.MaxWait
		}

		slog.Warn("Worker: Retrying request",
			"label", config.Label,
			"attempt", attempt+1,
			"max_retries", maxRetries,
			"wait_time", waitTime,
			"status", func() string {
				if resp != nil {
					return resp.Status
				}
				return "error"
			}(),
			"error", err)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(waitTime):
			continue
		}
	}

	return lastResp, lastErr
}
