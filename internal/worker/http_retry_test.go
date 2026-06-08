package worker

import (
	"regexp"
	"context"
	"cve-tracker/internal/db"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

type mockHTTPClient struct {
	responses []*http.Response
	errs      []error
	calls     int
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.calls >= len(m.responses) {
		return nil, fmt.Errorf("unexpected call")
	}
	resp := m.responses[m.calls]
	err := m.errs[m.calls]
	m.calls++
	return resp, err
}

func TestDoWithRetry_Success(t *testing.T) {
	client := &mockHTTPClient{
		responses: []*http.Response{
			{StatusCode: http.StatusOK},
		},
		errs: []error{nil},
	}

	resp, err := DoWithRetry(context.Background(), client, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
	}, func() (*http.Request, error) {
		return http.NewRequest("GET", "http://example.com", nil)
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 call, got %d", client.calls)
	}
}

func TestDoWithRetry_RetryThenSuccess(t *testing.T) {
	client := &mockHTTPClient{
		responses: []*http.Response{
			{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"1"}}},
			{StatusCode: http.StatusOK},
		},
		errs: []error{nil, nil},
	}

	start := time.Now()
	resp, err := DoWithRetry(context.Background(), client, RetryConfig{
		MaxRetries:  3,
		ShouldRetry: DefaultShouldRetry,
	}, func() (*http.Request, error) {
		return http.NewRequest("GET", "http://example.com", nil)
	})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if client.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", client.calls)
	}
	if duration < 1*time.Second {
		t.Fatalf("expected at least 1s wait, got %v", duration)
	}
}

func TestDoWithRetry_MaxRetries(t *testing.T) {
	client := &mockHTTPClient{
		responses: []*http.Response{
			{StatusCode: http.StatusTooManyRequests},
			{StatusCode: http.StatusTooManyRequests},
			{StatusCode: http.StatusTooManyRequests},
		},
		errs: []error{nil, nil, nil},
	}

	resp, err := DoWithRetry(context.Background(), client, RetryConfig{
		MaxRetries: 3,
		ShouldRetry: func(resp *http.Response, err error, attempt int) (bool, time.Duration) {
			return true, 1 * time.Millisecond
		},
	}, func() (*http.Request, error) {
		return http.NewRequest("GET", "http://example.com", nil)
	})

	if err != nil {
		t.Fatalf("expected nil error (returning last response), got %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
	if client.calls != 3 {
		t.Fatalf("expected 3 calls, got %d", client.calls)
	}
}

func TestGithubShouldRetry(t *testing.T) {
	tests := []struct {
		name        string
		resp        *http.Response
		err         error
		attempt     int
		wantRetry   bool
		minWaitSecs float64
	}{
		{
			name:      "Retry on error",
			err:       fmt.Errorf("network error"),
			attempt:   0,
			wantRetry: true,
		},
		{
			name:      "Retry on 403 with X-RateLimit-Reset",
			resp:      &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"X-RateLimit-Reset": []string{fmt.Sprintf("%d", time.Now().Add(10*time.Second).Unix())}}},
			attempt:   0,
			wantRetry: true,
		},
		{
			name:      "Retry on 500",
			resp:      &http.Response{StatusCode: http.StatusInternalServerError},
			attempt:   0,
			wantRetry: true,
		},
		{
			name:      "No retry on 200",
			resp:      &http.Response{StatusCode: http.StatusOK},
			attempt:   0,
			wantRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retry, wait := githubShouldRetry(tt.resp, tt.err, tt.attempt)
			if retry != tt.wantRetry {
				t.Errorf("githubShouldRetry() retry = %v, want %v", retry, tt.wantRetry)
			}
			if retry && wait <= 0 {
				t.Errorf("githubShouldRetry() wait = %v, want > 0", wait)
			}
		})
	}
}

func TestWorkerSync_GitHub_RateLimit(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	callCount := 0
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				// Simulate rate limit
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Header:     http.Header{"X-RateLimit-Reset": []string{"0"}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"total_count": 42}`)),
			}, nil
		},
	}

	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	mock.ExpectQuery("SELECT cve_id FROM cves").WillReturnRows(pgxmock.NewRows([]string{"cve_id"}).AddRow("CVE-LIMIT-1"))

	query := `
		UPDATE cves
		SET github_poc_count = u.github_poc_count
		FROM (SELECT unnest($1::text[]) as cve_id, unnest($2::int[]) as github_poc_count) as u
		WHERE cves.cve_id = u.cve_id
		AND cves.github_poc_count IS DISTINCT FROM u.github_poc_count
	`
	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs([]string{"CVE-LIMIT-1"}, []int32{42}).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	mock.ExpectExec("INSERT INTO worker_sync_stats").WithArgs("github_buzz_sync").WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Speed up the test
	originalGithubSyncDelay := githubSyncDelay
	githubSyncDelay = 0
	defer func() { githubSyncDelay = originalGithubSyncDelay }()

	w.syncGitHubBuzz(context.Background())

	if callCount < 2 {
		t.Errorf("expected GitHub retry, but only called %d times", callCount)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
