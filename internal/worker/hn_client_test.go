package worker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAlgoliaHNClient_FetchMentions(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.URL.String(), "query=CVE-2024-1234") {
					t.Errorf("expected query in URL, got %s", req.URL.String())
				}
				if !strings.Contains(req.URL.String(), "tags=story") {
					t.Errorf("expected tags=story in URL, got %s", req.URL.String())
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"nbHits": 1, "hits": [{"title": "Test Story", "objectID": "1"}]}`)),
				}, nil
			},
		}

		client := NewHNClient(httpClient)
		count, links, err := client.FetchMentions(context.Background(), "CVE-2024-1234")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 hit, got %d", count)
		}
		if len(links) != 1 {
			t.Errorf("expected 1 link, got %d", len(links))
		}
		if links[0]["title"] != "Test Story" || links[0]["url"] != "https://news.ycombinator.com/item?id=1" {
			t.Errorf("unexpected link content: %v", links[0])
		}
	})

	t.Run("APIError", func(t *testing.T) {
		httpClient := &MockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("error")),
				}, nil
			},
		}

		client := NewHNClient(httpClient)
		_, _, err := client.FetchMentions(context.Background(), "CVE-2024-1234")

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "status 500") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestAlgoliaHNClient_FetchMentions_Sanitization(t *testing.T) {
	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"nbHits": 1, "hits": [{"title": "<script>alert(1)</script>Safe Title", "objectID": "1"}]}`)),
			}, nil
		},
	}

	client := NewHNClient(httpClient)
	_, links, err := client.FetchMentions(context.Background(), "CVE-2024-1234")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}

	title := links[0]["title"]
	if strings.Contains(title, "<script>") {
		t.Errorf("title not sanitized: %s", title)
	}
	if title != "Safe Title" {
		t.Errorf("unexpected sanitized title: %s", title)
	}
}
