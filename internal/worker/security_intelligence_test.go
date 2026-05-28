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

func TestWorker_RedditSecurity(t *testing.T) {
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

	t.Run("InvalidCVEID", func(t *testing.T) {
		w := NewWorker(mock, rdb, &EmailSenderMock{}, &MockHTTPClient{})
		_, _, err := w.fetchRedditMentions(context.Background(), "INVALID-ID")
		if err == nil || !strings.Contains(err.Error(), "invalid CVE ID") {
			t.Errorf("expected error for invalid CVE ID, got %v", err)
		}
	})

	t.Run("LargeResponseBody", func(t *testing.T) {
		largeJSON := `{"data":{"children":[` + strings.Repeat(`{"data":{"title":"T","permalink":"/p"}},`, 100000) + `{"data":{"title":"T","permalink":"/p"}}]}}`
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(largeJSON)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)
		_, _, err := w.fetchRedditMentions(context.Background(), "CVE-2024-1234")
		if err == nil {
			t.Error("expected error for large response body (io.LimitReader should trigger error or truncated JSON)")
		}
	})

	t.Run("MaliciousPermalink", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data":{"children":[{"data":{"title":"Malicious","permalink":"//evil.com/a"}}]}}`)),
				}, nil
			},
		}
		w := NewWorker(mock, rdb, &EmailSenderMock{}, httpClient)
		count, links, err := w.fetchRedditMentions(context.Background(), "CVE-2024-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 0 || len(links) != 0 {
			t.Errorf("expected 0 links due to malicious permalink, got %d", count)
		}
	})
}

func TestWorker_HNSecurity(t *testing.T) {
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"nbHits":1,"hits":[{"title":"T","objectID":"123"}]}`)),
			}, nil
		},
	}
	hn := NewHNClient(httpClient)

	t.Run("InvalidCVEID", func(t *testing.T) {
		_, _, err := hn.FetchMentions(context.Background(), "INVALID")
		if err == nil || !strings.Contains(err.Error(), "invalid CVE ID") {
			t.Errorf("expected error for invalid CVE ID, got %v", err)
		}
	})

	t.Run("InvalidObjectID", func(t *testing.T) {
		httpClientMalicious := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"nbHits":1,"hits":[{"title":"T","objectID":"javascript:alert(1)"}]}`)),
				}, nil
			},
		}
		hnMalicious := NewHNClient(httpClientMalicious)
		_, links, err := hnMalicious.FetchMentions(context.Background(), "CVE-2024-1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(links) != 0 {
			t.Errorf("expected 0 links due to malicious objectID, got %d", len(links))
		}
	})
}
