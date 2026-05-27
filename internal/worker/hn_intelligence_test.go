package worker

import (
	"context"
	"cve-tracker/internal/db"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestWorker_HNRateLimit(t *testing.T) {
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
			if strings.Contains(req.URL.String(), "hn.algolia.com") {
				callCount++
				if callCount == 1 {
					return &http.Response{
						StatusCode: http.StatusTooManyRequests,
						Header:     http.Header{"Retry-After": []string{"0"}},
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"nbHits":1,"hits":[{"title":"HN Story","objectID":"123"}]}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}

	w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)

	t.Run("HNRateLimitRetry", func(t *testing.T) {
		count, links, err := w.fetchHNMentions(context.Background(), "CVE-2024-HN-LIMIT")
		if err != nil {
			t.Fatalf("fetchHNMentions failed: %v", err)
		}
		if callCount < 2 {
			t.Errorf("expected HN retry, but only called %d times", callCount)
		}
		if count != 1 {
			t.Errorf("expected 1 hit, got %d", count)
		}
		if len(links) != 1 || links[0]["title"] != "HN Story" {
			t.Errorf("unexpected links: %v", links)
		}
	})
}
