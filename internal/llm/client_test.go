package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cve-tracker/internal/config"
	"os"
)

func init() {
	_ = os.Setenv("LLM_DEBUG", "true")
}

type mockTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func TestExtractWithOllama(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/generate" {
				t.Errorf("expected path /api/generate, got %s", r.URL.Path)
			}
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			prompt := req["prompt"].(string)
			if !strings.Contains(prompt, "Vulnerability in Tomcat and JDK") {
				t.Errorf("prompt does not contain description")
			}
			resp := map[string]string{
				"response": `{"products": [{"vendor": "Apache", "product": "Tomcat", "version": "9.0.x"}, {"vendor": "Oracle", "product": "JDK", "version": "17"}]}`,
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		products, err := extractWithOllama(ctx, server.URL, "llama3", "Vulnerability in Tomcat and JDK")
		if err != nil {
			t.Fatalf("extractWithOllama failed: %v", err)
		}
		if len(products) != 2 {
			t.Fatalf("expected 2 products, got %d", len(products))
		}
	})

	t.Run("HTTPRequestError", func(t *testing.T) {
		ctx := context.Background()
		// Test error scenario properly without making external requests.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Close connection immediately to simulate error
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		server.Close() // Close it right away so request fails with connection refused
		_, err := extractWithOllama(ctx, server.URL, "model", "desc")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("Non200Status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Ollama Internal Error"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithOllama(ctx, server.URL, "model", "desc")
		if err == nil || !strings.Contains(err.Error(), "ollama returned status 500") {
			t.Fatalf("expected error containing status 500, got %v", err)
		}
	})

	t.Run("InvalidOllamaJSONBody", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithOllama(ctx, server.URL, "model", "desc")
		if err == nil {
			t.Fatal("expected json decode error, got nil")
		}
	})

	t.Run("InvalidOllamaResponseJSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]string{
				"response": "not-a-json-object",
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithOllama(ctx, server.URL, "model", "desc")
		if err == nil || !strings.Contains(err.Error(), "failed to parse ollama json response") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

}

func TestExtractWithMistral(t *testing.T) {
	t.Run("MissingAPIKey", func(t *testing.T) {
		ctx := context.Background()
		_, err := extractWithMistral(ctx, "", "model", "url", "desc")
		if err == nil || !strings.Contains(err.Error(), "api key is required") {
			t.Fatalf("expected api key required error, got %v", err)
		}
	})

	t.Run("HappyPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": `{"products": [{"vendor": "Arli", "product": "AI", "version": "1.0"}]}`,
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		products, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err != nil {
			t.Fatalf("extractWithMistral failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "Arli" {
			t.Fatalf("unexpected results: %+v", products)
		}
	})

	t.Run("MarkdownStripHappyPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": "```json\n" + `{"products": [{"vendor": "ArliMd", "product": "AI", "version": "1.0"}]}` + "\n```",
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		products, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err != nil {
			t.Fatalf("extractWithMistral failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "ArliMd" {
			t.Fatalf("unexpected results: %+v", products)
		}
	})

	t.Run("HTTPRequestError", func(t *testing.T) {
		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", "http://invalid-url-12345", "desc")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("EmptyChoicesError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err == nil || !strings.Contains(err.Error(), "mistral returned no choices") {
			t.Fatalf("expected no choices error, got %v", err)
		}
	})

	t.Run("InvalidJSONChoiceContent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": "not-json",
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err == nil || !strings.Contains(err.Error(), "failed to parse mistral json") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("Non200Status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err == nil || !strings.Contains(err.Error(), "mistral api error (status 401)") {
			t.Fatalf("expected unauthorized error, got %v", err)
		}
	})

	t.Run("InvalidChoiceJSONResponseFormat", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err == nil {
			t.Fatal("expected choice json error, got nil")
		}
	})

	t.Run("RateLimitRetrySuccess", func(t *testing.T) {
		// Override timeSleep to prevent waiting during tests
		oldTimeSleep := timeSleep
		timeSleep = func(d time.Duration) {}
		defer func() { timeSleep = oldTimeSleep }()

		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte("Rate limit, too many parallel requests"))
				return
			}
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": `{"products": [{"vendor": "ArliRetried", "product": "AI", "version": "2.0"}]}`,
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		products, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err != nil {
			t.Fatalf("extractWithMistral retry flow failed: %v", err)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
		if len(products) != 1 || products[0].Vendor != "ArliRetried" {
			t.Fatalf("unexpected product results: %+v", products)
		}
	})

	t.Run("RateLimitExceededFailure", func(t *testing.T) {
		// Override timeSleep to prevent waiting
		oldTimeSleep := timeSleep
		timeSleep = func(d time.Duration) {}
		defer func() { timeSleep = oldTimeSleep }()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Rate limit, too many parallel requests"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if !errors.Is(err, ErrRateLimit) {
			t.Fatalf("expected ErrRateLimit error, got %v", err)
		}
	})

	t.Run("NonRateLimitForbiddenError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("IP not whitelisted"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithMistral(ctx, "key", "model", server.URL, "desc")
		if err == nil || !strings.Contains(err.Error(), "mistral api error (status 403)") {
			t.Fatalf("expected forbidden error, got %v", err)
		}
	})
}

func TestExtractWithGemini(t *testing.T) {
	t.Run("MissingAPIKey", func(t *testing.T) {
		ctx := context.Background()
		_, err := extractWithGemini(ctx, "", "model", "v1", "desc")
		if err == nil || !strings.Contains(err.Error(), "gemini api key is required") {
			t.Fatalf("expected api key required error, got %v", err)
		}
	})

	t.Run("HappyPath", func(t *testing.T) {
		oldTransport := http.DefaultTransport
		defer func() { http.DefaultTransport = oldTransport }()

		http.DefaultTransport = &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Host, "generativelanguage.googleapis.com") {
					respObj := map[string]interface{}{
						"candidates": []map[string]interface{}{
							{
								"content": map[string]interface{}{
									"parts": []map[string]interface{}{
										{
											"text": `{"products": [{"vendor": "Google", "product": "Gemini", "version": "1.5"}]}`,
										},
									},
								},
							},
						},
					}
					respBytes, _ := json.Marshal(respObj)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(respBytes)),
						Header:     make(http.Header),
					}, nil
				}
				return nil, fmt.Errorf("unexpected request to %s", req.URL.String())
			},
		}

		ctx := context.Background()
		products, err := extractWithGemini(ctx, "key", "gemini-1.5-flash", "v1", "desc")
		if err != nil {
			t.Fatalf("extractWithGemini failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "Google" {
			t.Fatalf("unexpected products result: %+v", products)
		}
	})

	t.Run("GenerateContentError", func(t *testing.T) {
		oldTransport := http.DefaultTransport
		defer func() { http.DefaultTransport = oldTransport }()

		http.DefaultTransport = &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Host, "generativelanguage.googleapis.com") {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(strings.NewReader("Gemini Internal Error")),
						Header:     make(http.Header),
					}, nil
				}
				return nil, fmt.Errorf("unexpected request")
			},
		}

		ctx := context.Background()
		_, err := extractWithGemini(ctx, "key", "gemini-1.5-flash", "v1", "desc")
		if err == nil {
			t.Fatal("expected Gemini content error, got nil")
		}
	})

	t.Run("InvalidResponseJSON", func(t *testing.T) {
		oldTransport := http.DefaultTransport
		defer func() { http.DefaultTransport = oldTransport }()

		http.DefaultTransport = &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Host, "generativelanguage.googleapis.com") {
					respObj := map[string]interface{}{
						"candidates": []map[string]interface{}{
							{
								"content": map[string]interface{}{
									"parts": []map[string]interface{}{
										{
											"text": `{invalid-json`,
										},
									},
								},
							},
						},
					}
					respBytes, _ := json.Marshal(respObj)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(respBytes)),
						Header:     make(http.Header),
					}, nil
				}
				return nil, fmt.Errorf("unexpected request")
			},
		}

		ctx := context.Background()
		_, err := extractWithGemini(ctx, "key", "gemini-1.5-flash", "v1", "desc")
		if err == nil {
			t.Fatal("expected Gemini json decode error, got nil")
		}
	})
}

func TestExtractWithOpenAI(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/chat/completions" {
				t.Errorf("expected path /chat/completions, got %s", r.URL.Path)
			}
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": `{"products": [{"vendor": "OpenAI", "product": "GPT-4", "version": "1.0"}]}`,
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		products, err := extractWithOpenAI(ctx, "key", "model", server.URL, "desc")
		if err != nil {
			t.Fatalf("extractWithOpenAI failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "OpenAI" {
			t.Fatalf("unexpected results: %+v", products)
		}
	})

	t.Run("MarkdownStripHappyPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": "```json\n" + `{"products": [{"vendor": "OpenAIMd", "product": "GPT-4", "version": "1.0"}]}` + "\n```",
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		products, err := extractWithOpenAI(ctx, "key", "model", server.URL, "desc")
		if err != nil {
			t.Fatalf("extractWithOpenAI failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "OpenAIMd" {
			t.Fatalf("unexpected results: %+v", products)
		}
	})

	t.Run("EmptyAPIKeyAuth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth != "" {
				t.Errorf("expected empty Authorization header, got %s", auth)
			}
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": `{"products": []}`,
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithOpenAI(ctx, "", "model", server.URL, "desc")
		if err != nil {
			t.Fatalf("extractWithOpenAI failed: %v", err)
		}
	})

	t.Run("Non200Status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("OpenAI Error"))
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := extractWithOpenAI(ctx, "key", "model", server.URL, "desc")
		if err == nil || !strings.Contains(err.Error(), "openai api error (status 500)") {
			t.Fatalf("expected 500 error, got %v", err)
		}
	})
}

func TestExtractVendorProduct(t *testing.T) {
	t.Run("UnsupportedProvider", func(t *testing.T) {
		config.AppConfig.LLMProvider = "unsupported-vendor-name"
		ctx := context.Background()
		_, err := ExtractVendorProduct(ctx, "desc", []string{})
		if err == nil || !strings.Contains(err.Error(), "no valid llm providers configured") {
			t.Fatalf("expected no valid providers error, got %v", err)
		}
	})

	t.Run("SemaphoreCancellation", func(t *testing.T) {
		// Acquire semaphore manually
		llmSemaphore <- struct{}{}
		defer func() { <-llmSemaphore }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel the context

		config.AppConfig.LLMProvider = "ollama"
		_, err := ExtractVendorProduct(ctx, "desc", []string{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("OllamaPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]string{
				"response": `{"products": [{"vendor": "OllamaTest", "product": "P", "version": "1.0"}]}`,
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config.AppConfig.LLMProvider = "ollama"
		config.AppConfig.LLMEndpoint = server.URL
		config.AppConfig.LLMModel = "llama3"

		products, err := ExtractVendorProduct(context.Background(), "desc", []string{})
		if err != nil {
			t.Fatalf("ExtractVendorProduct Ollama path failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "OllamaTest" {
			t.Fatalf("unexpected product results: %+v", products)
		}
	})

	t.Run("MistralPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": `{"products": [{"vendor": "ArliTest", "product": "P", "version": "1.0"}]}`,
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config.AppConfig.LLMProvider = "mistral"
		config.AppConfig.MistralAPIKey = "dummy-key"
		config.AppConfig.MistralModel = "model"
		config.AppConfig.MistralEndpoint = server.URL

		products, err := ExtractVendorProduct(context.Background(), "desc", []string{})
		if err != nil {
			t.Fatalf("ExtractVendorProduct Mistral path failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "ArliTest" {
			t.Fatalf("unexpected product results: %+v", products)
		}
	})

	t.Run("GeminiPath", func(t *testing.T) {
		oldTransport := http.DefaultTransport
		defer func() { http.DefaultTransport = oldTransport }()

		http.DefaultTransport = &mockTransport{
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Host, "generativelanguage.googleapis.com") {
					respObj := map[string]interface{}{
						"candidates": []map[string]interface{}{
							{
								"content": map[string]interface{}{
									"parts": []map[string]interface{}{
										{
											"text": `{"products": [{"vendor": "GeminiTest", "product": "P", "version": "1.0"}]}`,
										},
									},
								},
							},
						},
					}
					respBytes, _ := json.Marshal(respObj)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(respBytes)),
						Header:     make(http.Header),
					}, nil
				}
				return nil, fmt.Errorf("unexpected request")
			},
		}

		config.AppConfig.LLMProvider = "gemini31flashlite"
		config.AppConfig.GeminiAPIKey = "dummy-key"
		config.AppConfig.Gemini31LiteModel = "gemini-1.5-flash"
		config.AppConfig.GeminiAPIVersion = "v1"

		products, err := ExtractVendorProduct(context.Background(), "desc", []string{})
		if err != nil {
			t.Fatalf("ExtractVendorProduct Gemini path failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "GeminiTest" {
			t.Fatalf("unexpected product results: %+v", products)
		}
	})

	t.Run("OpenAIPath", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]string{
							"content": `{"products": [{"vendor": "OpenAITest", "product": "P", "version": "1.0"}]}`,
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config.AppConfig.LLMProvider = "openai"
		config.AppConfig.OpenAIAPIKey = "dummy-key"
		config.AppConfig.OpenAIModel = "model"
		config.AppConfig.OpenAIEndpoint = server.URL

		products, err := ExtractVendorProduct(context.Background(), "desc", []string{})
		if err != nil {
			t.Fatalf("ExtractVendorProduct OpenAI path failed: %v", err)
		}
		if len(products) != 1 || products[0].Vendor != "OpenAITest" {
			t.Fatalf("unexpected product results: %+v", products)
		}
	})

	t.Run("ReferencesFormatting", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode req: %v", err)
			}
			prompt, ok := req["prompt"].(string)
			if !ok {
				t.Fatalf("prompt not a string or missing")
			}

			expectedContext := "test-desc\n\nReferences:\nref1\nref2"
			if !strings.Contains(prompt, expectedContext) {
				t.Errorf("expected context %q not found in prompt: %s", expectedContext, prompt)
			}

			resp := map[string]string{"response": `{"products": []}`}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config.AppConfig.LLMProvider = "ollama"
		config.AppConfig.LLMEndpoint = server.URL
		config.AppConfig.LLMModel = "model"

		_, _ = ExtractVendorProduct(context.Background(), "test-desc", []string{"ref1", "ref2"})
	})

	t.Run("ProviderError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Ollama Internal Error"))
		}))
		defer server.Close()

		config.AppConfig.LLMProvider = "ollama"
		config.AppConfig.LLMEndpoint = server.URL
		config.AppConfig.LLMModel = "model"

		_, err := ExtractVendorProduct(context.Background(), "desc", []string{})
		if err == nil || !strings.Contains(err.Error(), "ollama returned status 500") {
			t.Fatalf("expected ollama error, got %v", err)
		}
	})
}

func TestSetCooldownAndIsCooledDown(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		duration     time.Duration
		sleep        time.Duration
		expectedCool bool
	}{
		{
			name:         "Provider in cooldown",
			provider:     "test_provider_1",
			duration:     10 * time.Minute,
			sleep:        0,
			expectedCool: true,
		},
		{
			name:         "Provider not in cooldown (unknown)",
			provider:     "unknown_provider",
			duration:     0,
			sleep:        0,
			expectedCool: false,
		},
		{
			name:         "Provider cooldown expired",
			provider:     "test_provider_2",
			duration:     1 * time.Millisecond,
			sleep:        50 * time.Millisecond,
			expectedCool: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.duration > 0 {
				setCooldown(tc.provider, tc.duration)
			}

			if tc.sleep > 0 {
				time.Sleep(tc.sleep)
			}

			isCool := isCooledDown(tc.provider)
			if isCool != tc.expectedCool {
				t.Errorf("Expected isCooledDown to be %v for provider %s, got %v", tc.expectedCool, tc.provider, isCool)
			}
		})
	}
}

func TestGeminiPauseInterval(t *testing.T) {
	t.Run("default is 15 RPM (4s)", func(t *testing.T) {
		t.Setenv("GEMINI_RPM", "")
		if got := geminiPauseInterval(); got != 4*time.Second {
			t.Errorf("default pause = %v, want 4s (15 RPM)", got)
		}
	})
	t.Run("honors GEMINI_RPM override", func(t *testing.T) {
		t.Setenv("GEMINI_RPM", "5")
		if got := geminiPauseInterval(); got != 12*time.Second {
			t.Errorf("pause at 5 RPM = %v, want 12s", got)
		}
	})
	t.Run("ignores invalid/zero override", func(t *testing.T) {
		t.Setenv("GEMINI_RPM", "0")
		if got := geminiPauseInterval(); got != 4*time.Second {
			t.Errorf("pause with GEMINI_RPM=0 = %v, want default 4s", got)
		}
		t.Setenv("GEMINI_RPM", "notanumber")
		if got := geminiPauseInterval(); got != 4*time.Second {
			t.Errorf("pause with invalid GEMINI_RPM = %v, want default 4s", got)
		}
	})
}

func TestGeminiDailyLimit(t *testing.T) {
	t.Run("default is 500", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "")
		if got := geminiDailyLimit(); got != 500 {
			t.Errorf("default limit = %d, want 500", got)
		}
	})
	t.Run("honors override", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "1000")
		if got := geminiDailyLimit(); got != 1000 {
			t.Errorf("limit = %d, want 1000", got)
		}
	})
	t.Run("zero disables tracking", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "0")
		if got := geminiDailyLimit(); got != 0 {
			t.Errorf("limit = %d, want 0 (disabled)", got)
		}
	})
	t.Run("invalid falls back to default", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "notanumber")
		if got := geminiDailyLimit(); got != 500 {
			t.Errorf("limit = %d, want default 500", got)
		}
	})
}

func TestGoogleFailover(t *testing.T) {
	t.Run("resolves all failover providers with correct defaults", func(t *testing.T) {
		for _, tc := range []struct {
			provider   string
			structured bool
			defRPM     int
			defRPD     int
		}{
			{"gemini35flash", true, 5, 20},
			{"gemini3flash", true, 5, 20},
		} {
			f, ok := googleFailoverFor(tc.provider)
			if !ok {
				t.Errorf("%s should resolve", tc.provider)
				continue
			}
			if f.structured != tc.structured {
				t.Errorf("%s structured = %v, want %v", tc.provider, f.structured, tc.structured)
			}
			if f.defRPM != tc.defRPM || f.defRPD != tc.defRPD {
				t.Errorf("%s defaults = %d/%d, want %d/%d", tc.provider, f.defRPM, f.defRPD, tc.defRPM, tc.defRPD)
			}
		}
		if _, ok := googleFailoverFor("gemini31flashlite"); ok {
			t.Error("primary gemini31flashlite should not be a failover provider")
		}
		if _, ok := googleFailoverFor("mistral"); ok {
			t.Error("mistral should not resolve as a failover")
		}
	})
	t.Run("pace honors RPM override and default", func(t *testing.T) {
		f, _ := googleFailoverFor("gemini35flash")
		t.Setenv("GEMINI35FLASH_RPM", "")
		if got := googleFailoverPace(f); got != 12*time.Second { // 5 RPM default
			t.Errorf("default gemini35flash pace = %v, want 12s (5 RPM)", got)
		}
		t.Setenv("GEMINI35FLASH_RPM", "15")
		if got := googleFailoverPace(f); got != 4*time.Second {
			t.Errorf("gemini35flash pace at 15 RPM = %v, want 4s", got)
		}
		// Short (.env/docker-compose) name works as fallback
		t.Setenv("GEMINI35FLASH_RPM", "")
		t.Setenv("GEMINI35_RPM", "6")
		if got := googleFailoverPace(f); got != 10*time.Second {
			t.Errorf("gemini35flash pace via GEMINI35_RPM fallback = %v, want 10s", got)
		}
	})
	t.Run("daily limit honors override, default, and zero", func(t *testing.T) {
		f, _ := googleFailoverFor("gemini35flash")
		t.Setenv("GEMINI35FLASH_RPD", "")
		if got := googleFailoverDailyLimit(f); got != 20 {
			t.Errorf("default gemini35flash limit = %d, want 20", got)
		}
		t.Setenv("GEMINI35FLASH_RPD", "0")
		if got := googleFailoverDailyLimit(f); got != 0 {
			t.Errorf("gemini35flash limit = %d, want 0 (disabled)", got)
		}
		// Short (.env/docker-compose) name works as fallback
		t.Setenv("GEMINI35FLASH_RPD", "")
		t.Setenv("GEMINI35_RPD", "50")
		if got := googleFailoverDailyLimit(f); got != 50 {
			t.Errorf("gemini35flash limit via GEMINI35_RPD fallback = %d, want 50", got)
		}
	})
}

func TestGeminiDailyQuotaExceeded(t *testing.T) {
	orig := geminiRPDIncr
	t.Cleanup(func() { geminiRPDIncr = orig })

	t.Run("under limit allows", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "500")
		geminiRPDIncr = func(context.Context) (int64, error) { return 1, nil }
		if geminiDailyQuotaExceeded(context.Background()) {
			t.Error("expected allowed when count (1) <= limit (500)")
		}
	})
	t.Run("at limit allows", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "500")
		geminiRPDIncr = func(context.Context) (int64, error) { return 500, nil }
		if geminiDailyQuotaExceeded(context.Background()) {
			t.Error("expected allowed when count (500) == limit (500)")
		}
	})
	t.Run("over limit blocks", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "500")
		geminiRPDIncr = func(context.Context) (int64, error) { return 501, nil }
		if !geminiDailyQuotaExceeded(context.Background()) {
			t.Error("expected blocked when count (501) > limit (500)")
		}
	})
	t.Run("redis error fails open", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "500")
		geminiRPDIncr = func(context.Context) (int64, error) { return 0, errors.New("redis down") }
		if geminiDailyQuotaExceeded(context.Background()) {
			t.Error("expected fail-open (allowed) on redis error")
		}
	})
	t.Run("disabled never blocks and never increments", func(t *testing.T) {
		t.Setenv("GEMINI_RPD", "0")
		called := false
		geminiRPDIncr = func(context.Context) (int64, error) { called = true; return 999999, nil }
		if geminiDailyQuotaExceeded(context.Background()) {
			t.Error("expected allowed when tracking disabled")
		}
		if called {
			t.Error("expected no Redis increment when tracking disabled")
		}
	})
}

func TestDurationUntilUTCMidnight(t *testing.T) {
	d := durationUntilUTCMidnight()
	if d <= 0 || d > 24*time.Hour {
		t.Errorf("durationUntilUTCMidnight = %v, want (0, 24h]", d)
	}
}

func TestGoogleFailoverQuotaExceeded(t *testing.T) {
	orig := googleFailoverRPDIncr
	t.Cleanup(func() { googleFailoverRPDIncr = orig })

	tests := []struct {
		name     string
		rpdStr   string
		incrRet  int64
		incrErr  error
		expected bool
	}{
		{
			name:     "under limit allows",
			rpdStr:   "500",
			incrRet:  1,
			incrErr:  nil,
			expected: false,
		},
		{
			name:     "at limit allows",
			rpdStr:   "500",
			incrRet:  500,
			incrErr:  nil,
			expected: false,
		},
		{
			name:     "over limit blocks",
			rpdStr:   "500",
			incrRet:  501,
			incrErr:  nil,
			expected: true,
		},
		{
			name:     "redis error fails open",
			rpdStr:   "500",
			incrRet:  0,
			incrErr:  errors.New("redis down"),
			expected: false,
		},
		{
			name:     "disabled never blocks",
			rpdStr:   "0",
			incrRet:  999999,
			incrErr:  nil,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GEMINI35FLASH_RPD", tc.rpdStr)
			f, _ := googleFailoverFor("gemini35flash")

			called := false
			googleFailoverRPDIncr = func(ctx context.Context, prefix string) (int64, error) {
				called = true
				return tc.incrRet, tc.incrErr
			}

			result := googleFailoverQuotaExceeded(context.Background(), f)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}

			if tc.rpdStr == "0" && called {
				t.Error("expected no Redis increment when tracking disabled")
			}
		})
	}
}
