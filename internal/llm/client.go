package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
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

var ErrRateLimit = errors.New("llm rate limit exceeded")

// Global semaphore to limit LLM concurrency to 1.
// This ensures that only one LLM request is processed at a time across the entire application.
var llmSemaphore = make(chan struct{}, 1)

// ExtractVendorProduct chooses the appropriate provider (Gemini, Ollama, or ArliAI) to extract all vendor/product/version names.
func ExtractVendorProduct(ctx context.Context, description string) ([]ProductResult, error) {
	// Acquire semaphore (queue up if another job is running)
	select {
	case llmSemaphore <- struct{}{}:
		defer func() { <-llmSemaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	switch config.AppConfig.LLMProvider {
	case "gemini":
		return extractWithGemini(ctx, config.AppConfig.GeminiAPIKey, config.AppConfig.GeminiModel, description)
	case "ollama":
		return extractWithOllama(ctx, config.AppConfig.LLMEndpoint, config.AppConfig.LLMModel, description)
	case "arliai":
		return extractWithArliAI(ctx, config.AppConfig.ArliAIAPIKey, config.AppConfig.ArliAIModel, config.AppConfig.ArliAIEndpoint, description)
	default:
		return nil, fmt.Errorf("unsupported llm provider: %s", config.AppConfig.LLMProvider)
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

	prompt := `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from this CVE description. 

RULES:
1. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
2. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
3. If multiple products are mentioned, list them all.

Input: "Azure Service Fabric for Linux RCE affects version 9.1 before 9.1.2498.1, 10.0 before 10.0.2345.1, and 10.1 before 10.1.2308.1"
Output: {"products": [
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "9.1 < 9.1.2498.1"},
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "10.0 < 10.0.2345.1"},
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "10.1 < 10.1.2308.1"}
]}

Description: ` + description
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

	prompt := `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from this CVE description. 

RULES:
1. Return results ONLY as a JSON object with a key "products" containing a list of objects.
2. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
3. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
4. If multiple products are mentioned, list them all.

EXAMPLES:
Input: "Vulnerability in Cisco IOS before 15.1"
Output: {"products": [{"vendor": "Cisco", "product": "IOS", "version": "< 15.1"}]}

Input: "Azure Service Fabric for Linux RCE affects version 9.1 before 9.1.2498.1, 10.0 before 10.0.2345.1, and 10.1 before 10.1.2308.1"
Output: {"products": [
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "9.1 < 9.1.2498.1"},
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "10.0 < 10.0.2345.1"},
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "10.1 < 10.1.2308.1"}
]}

Description: ` + description

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
func extractWithArliAI(ctx context.Context, apiKey, model, endpoint, description string) ([]ProductResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("arliai api key is required")
	}

	systemPrompt := `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from this CVE description. 

RULES:
1. Return results ONLY as a JSON object with a key "products" containing a list of objects.
2. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
3. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
4. If multiple products are mentioned, list them all.

EXAMPLES:
Input: "Vulnerability in Cisco IOS before 15.1"
Output: {"products": [{"vendor": "Cisco", "product": "IOS", "version": "< 15.1"}]}

Input: "The debug command in Sendmail is enabled"
Output: {"products": [{"vendor": "Sendmail", "product": "Sendmail", "version": null}]}

Input: "Azure Service Fabric for Linux RCE affects version 9.1 before 9.1.2498.1, 10.0 before 10.0.2345.1, and 10.1 before 10.1.2308.1"
Output: {"products": [
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "9.1 < 9.1.2498.1"},
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "10.0 < 10.0.2345.1"},
  {"vendor": "Microsoft", "product": "Azure Service Fabric (Linux)", "version": "10.1 < 10.1.2308.1"}
]}`

	if os.Getenv("LLM_DEBUG") == "true" {
		log.Printf("LLM: [DEBUG] ArliAI System Prompt: %s", systemPrompt)
		log.Printf("LLM: [DEBUG] ArliAI Description: %s", description)
	}

	payload := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": "Description: " + description},
		},
		"temperature":     0,
		"response_format": map[string]string{"type": "json_object"},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: time.Duration(config.AppConfig.LLMTimeout) * time.Second}
	
	var lastErr error
	for i := 0; i < 3; i++ {
		if i > 0 {
			// Backoff before retry
			wait := time.Duration(i*2) * time.Second
			log.Printf("LLM: [RETRY] ArliAI hit limit, waiting %v before retry %d/3...", wait, i)
			time.Sleep(wait)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "parallel") || strings.Contains(string(body), "rate") || strings.Contains(string(body), "limit") {
				lastErr = ErrRateLimit
				// Reset request body for retry if possible (re-create request)
				req, _ = http.NewRequestWithContext(ctx, "POST", endpoint+"/chat/completions", bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+apiKey)
				continue
			}
			return nil, fmt.Errorf("arliai api error (status %d): %s", resp.StatusCode, string(body))
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("arliai api error (status %d): %s", resp.StatusCode, string(body))
		}

		var chatResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
			return nil, err
		}

		if len(chatResp.Choices) == 0 {
			return nil, fmt.Errorf("arliai returned no choices")
		}

		content := chatResp.Choices[0].Message.Content
		if os.Getenv("LLM_DEBUG") == "true" {
			log.Printf("LLM: [DEBUG] ArliAI Raw Response: %s", content)
		}

		// Clean JSON if the model wrapped it in markdown code blocks
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)

		var res ExtractionResponse
		if err := json.Unmarshal([]byte(content), &res); err != nil {
			return nil, fmt.Errorf("failed to parse arliai json: %w (content: %s)", err, content)
		}

		return res.Products, nil
	}

	return nil, lastErr
}
