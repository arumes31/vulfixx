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

	cveID := "CVE-2024-CACHE-TEST"

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

func TestWorker_FetchOSINTLinks_RedisNil(t *testing.T) {
	// Setup DB mock but use nil Redis
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	var hnCallCount, redditCallCount int32

	// Setup custom mock HTTP client for tracking API calls instead of real HTTP client
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "algolia.com") {
				atomic.AddInt32(&hnCallCount, 1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"nbHits":1,"hits":[{"title":"HN Story","objectID":"123"}]}`)),
				}, nil
			}
			if strings.Contains(req.URL.String(), "reddit.com") {
				atomic.AddInt32(&redditCallCount, 1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data":{"children":[{"data":{"title":"Reddit Post","permalink":"/r/post"}}]}}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}

	w := NewWorker(mock, nil, &EmailSenderMock{}, httpClient) // Redis is nil
	// Explicitly setup HNClient as NewWorker might not set it up correctly with custom mocked HTTP client inside NewHNClient
	w.HNClient = NewHNClient(httpClient)

	cveID := "CVE-2024-12345"

	// Fetch should not panic, and should call the APIs
	data := w.fetchOSINTLinks(context.Background(), cveID)

	// We expect HN and Reddit APIs to have been called once each
	if atomic.LoadInt32(&hnCallCount) != 1 {
		t.Errorf("Expected 1 call to HN API, got %d", atomic.LoadInt32(&hnCallCount))
	}
	if atomic.LoadInt32(&redditCallCount) != 1 {
		t.Errorf("Expected 1 call to Reddit API, got %d", atomic.LoadInt32(&redditCallCount))
	}

	// We expect data to contain reddit and hn
	if _, ok := data["hn"]; !ok {
		t.Errorf("Expected data to contain 'hn' key")
	}
	if _, ok := data["reddit"]; !ok {
		t.Errorf("Expected data to contain 'reddit' key")
	}
}
