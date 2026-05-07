package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractWithOllama(t *testing.T) {
	// Mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("expected path /api/generate, got %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}

		// Check if prompt contains the description
		prompt := req["prompt"].(string)
		if !contains(prompt, "Vulnerability in Tomcat and JDK") {
			t.Errorf("prompt does not contain description")
		}

		// Return mock response
		resp := map[string]string{
			"response": `{"products": [{"vendor": "Apache", "product": "Tomcat", "version": "9.0.x"}, {"vendor": "Oracle", "product": "JDK", "version": "17"}]}`,
		}
		json.NewEncoder(w).Encode(resp)
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

	if products[0].Vendor != "Apache" {
		t.Errorf("expected vendor Apache, got %s", products[0].Vendor)
	}
	if products[1].Vendor != "Oracle" {
		t.Errorf("expected vendor Oracle, got %s", products[1].Vendor)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
