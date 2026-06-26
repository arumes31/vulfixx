package worker

import (
	"context"
	"cve-tracker/internal/db"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestWorker_FetchOSINTLinks_Caching(t *testing.T) {
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

	var callCount atomic.Int32
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			callCount.Add(1)
			if strings.Contains(req.URL.String(), "hn.algolia.com") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"hits":[{"title":"HN Story","objectID":"123"}]}`)),
				}, nil
			}
			if strings.Contains(req.URL.String(), "reddit.com") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data":{"children":[{"data":{"title":"Reddit Post","permalink":"/r/sec/1"}}]}}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}

	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	cveID := "CVE-2024-1234"

	// First call - should fetch from APIs
	data1 := w.fetchOSINTLinks(context.Background(), cveID)
	if callCount.Load() == 0 {
		t.Error("Expected API calls on first fetch, but got none")
	}

	currentCallCount := callCount.Load()

	// Second call - should fetch from cache
	data2 := w.fetchOSINTLinks(context.Background(), cveID)
	if callCount.Load() != currentCallCount {
		t.Errorf("Expected no new API calls on second fetch (cached), but callCount increased from %d to %d", currentCallCount, callCount.Load())
	}

	// Verify data is the same
	if len(data1) != len(data2) {
		t.Errorf("Data mismatch: first call returned %d entries, second call returned %d entries", len(data1), len(data2))
	}
}

func TestWorker_FetchOSINTLinks_RedisFailure(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run failed: %v", err)
	}
	// We won't defer mr.Close() here because we will close it manually to simulate failure
	// We use MaxRetries = 1 so the tests run faster when simulated failure occurs
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: 1})
	defer rdb.Close()

	var callCount atomic.Int32
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			callCount.Add(1)
			if strings.Contains(req.URL.String(), "hn.algolia.com") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"hits":[{"title":"HN Story","objectID":"123"}]}`)),
				}, nil
			}
			if strings.Contains(req.URL.String(), "reddit.com") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data":{"children":[{"data":{"title":"Reddit Post","permalink":"/r/sec/1"}}]}}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}

	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	cveID := "CVE-2024-1234"

	// Close miniredis to simulate Redis failure
	mr.Close()

	// Call fetchOSINTLinks, it should handle the Redis failure gracefully and fallback to API
	data := w.fetchOSINTLinks(context.Background(), cveID)

	// Ensure API calls were made
	if callCount.Load() == 0 {
		t.Error("Expected API calls when Redis fails, but got none")
	}

	// Ensure data is returned
	if len(data) == 0 {
		t.Error("Expected data to be returned even when Redis fails, but got none")
	}
}
