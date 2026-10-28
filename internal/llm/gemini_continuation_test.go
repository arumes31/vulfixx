package llm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestExtractWithGeminiDoesNotContinue(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	calls := 0
	http.DefaultTransport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != "generativelanguage.googleapis.com" {
				return nil, fmt.Errorf("unexpected request host: %s", req.URL.Host)
			}
			calls++
			body := `{"candidates":[{"content":{"role":"model","parts":[` +
				`{"text":"{\"products\":[{\"vendor\":\"Google\",\"product\":\"Gemini\",\"version\":\"1.5\"}]}"}]},` +
				`"finishReason":"CONTINUATION","continuationToken":"aG9wLTE="}]}`
			if calls > 1 {
				body = `{"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}]}`
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	}

	products, err := extractWithGemini(
		context.Background(),
		"test-key",
		"gemini-1.5-flash",
		"v1",
		"description",
	)
	if calls != 1 {
		t.Fatalf("one quota-counted extraction made %d requests; want 1", calls)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(products) != 1 || products[0].Vendor != "Google" {
		t.Fatalf("unexpected products: %+v", products)
	}
}
