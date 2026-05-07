package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"google.golang.org/genai"
	"cve-tracker/internal/config"
)

type ProductResult struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

type ExtractionResponse struct {
	Products []ProductResult `json:"products"`
}

// Global semaphore to limit LLM concurrency to 1.
// This ensures that only one LLM request is processed at a time across the entire application.
var llmSemaphore = make(chan struct{}, 1)

// ExtractVendorProduct chooses the appropriate provider (Gemini or Ollama) to extract all vendor/product/version names.
func ExtractVendorProduct(ctx context.Context, provider, apiKey, endpoint, model, description string) ([]ProductResult, error) {
	// Acquire semaphore (queue up if another job is running)
	select {
	case llmSemaphore <- struct{}{}:
		defer func() { <-llmSemaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	switch provider {
	case "gemini":
		return extractWithGemini(ctx, apiKey, model, description)
	case "ollama":
		return extractWithOllama(ctx, endpoint, model, description)
	default:
		return nil, fmt.Errorf("unsupported llm provider: %s", provider)
	}
}

func extractWithGemini(ctx context.Context, apiKey, model, description string) ([]ProductResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("gemini api key is required")
	}

	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gemini client: %w", err)
	}

	schema := &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"products": {
				Type: genai.TypeArray,
				Items: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"vendor":  {Type: genai.TypeString, Description: "The software or hardware vendor name"},
						"product": {Type: genai.TypeString, Description: "The software or hardware product name"},
						"version": {Type: genai.TypeString, Description: "The affected version or version range (e.g. 'before 1.2.3', '2.x')"},
					},
					Required: []string{"vendor", "product", "version"},
				},
			},
		},
		Required: []string{"products"},
	}

	config := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseSchema:   schema,
		Temperature:      genai.Ptr[float32](0.0),
	}

	prompt := fmt.Sprintf("Extract ALL affected vendor(s), product name(s), and version(s) from this CVE description: %s", description)
	if os.Getenv("LLM_DEBUG") == "true" {
		log.Printf("LLM: [DEBUG] Gemini Prompt: %s", prompt)
	}

	result, err := client.Models.GenerateContent(ctx, model, genai.Text(prompt), config)
	if err != nil {
		return nil, err
	}

	if os.Getenv("LLM_DEBUG") == "true" {
		log.Printf("LLM: [DEBUG] Gemini Raw Response: %s", result.Text())
	}

	var res ExtractionResponse
	if err := json.Unmarshal([]byte(result.Text()), &res); err != nil {
		return nil, err
	}
	return res.Products, nil
}

func extractWithOllama(ctx context.Context, endpoint, model, description string) ([]ProductResult, error) {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}

	prompt := fmt.Sprintf(`Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from this CVE description. 
Return the result ONLY as a JSON object with a key "products" containing a list of objects with "vendor", "product", and "version".
Description: %s`, description)

	if os.Getenv("LLM_DEBUG") == "true" {
		log.Printf("LLM: [DEBUG] Ollama Prompt: %s", prompt)
	}

	payload := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Duration(config.AppConfig.LLMTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w (is ollama running at %s?)", err, endpoint)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, err
	}

	if os.Getenv("LLM_DEBUG") == "true" {
		log.Printf("LLM: [DEBUG] Ollama Raw Response: %s", ollamaResp.Response)
	}

	var res ExtractionResponse
	if err := json.Unmarshal([]byte(ollamaResp.Response), &res); err != nil {
		return nil, fmt.Errorf("failed to parse ollama json response: %w, text: %s", err, ollamaResp.Response)
	}

	return res.Products, nil
}
