package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"cve-tracker/internal/config"
	"google.golang.org/genai"
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

// Cooldown state to track exhausted providers
var (
	providerCooldowns = make(map[string]time.Time)
	cooldownMutex     sync.RWMutex
)

func setCooldown(provider string, duration time.Duration) {
	cooldownMutex.Lock()
	defer cooldownMutex.Unlock()
	providerCooldowns[provider] = time.Now().Add(duration)
	slog.Info("LLM: [COOLDOWN] Provider is exhausted. Cooling down...", "provider", provider, "duration", duration)
}

func isCooledDown(provider string) bool {
	cooldownMutex.RLock()
	defer cooldownMutex.RUnlock()
	until, exists := providerCooldowns[provider]
	if !exists {
		return false
	}
	if time.Now().After(until) {
		return false
	}
	return true
}

// ExtractVendorProduct chooses the appropriate provider(s) (Gemini, Ollama, or ArliAI) to extract all vendor/product/version names.
// It supports a fallback chain if LLM_PROVIDER is a comma-separated list (e.g. "gemini,arliai").
func ExtractVendorProduct(ctx context.Context, description string, references []string) ([]ProductResult, error) {
	// Acquire semaphore (queue up if another job is running)
	select {
	case llmSemaphore <- struct{}{}:
		defer func() { <-llmSemaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	fullContext := fmt.Sprintf("%s\n\nReferences:\n%s", description, strings.Join(references, "\n"))
	providers := strings.Split(config.AppConfig.LLMProvider, ",")

	var lastErr error
	for _, p := range providers {
		p = strings.TrimSpace(p)
		if p == "" || p == "none" {
			continue
		}

		if isCooledDown(p) {
			slog.Debug("LLM: skipping provider on cooldown", "provider", p)
			continue
		}

		var results []ProductResult
		var err error

		switch p {
		case "gemini":
			results, err = extractWithGemini(ctx, config.AppConfig.GeminiAPIKey, config.AppConfig.GeminiModel, config.AppConfig.GeminiAPIVersion, fullContext)
		case "ollama":
			results, err = extractWithOllama(ctx, config.AppConfig.LLMEndpoint, config.AppConfig.LLMModel, fullContext)
		case "arliai":
			results, err = extractWithArliAI(ctx, config.AppConfig.ArliAIAPIKey, config.AppConfig.ArliAIModel, config.AppConfig.ArliAIEndpoint, fullContext)
		default:
			slog.Warn("LLM: [WARN] Unsupported provider in chain", "provider", p)
			continue
		}

		if err == nil {
			// Proactive rate limiting for Gemini free tier (15 RPM limit)
			if p == "gemini" {
				slog.Debug("LLM: successful Gemini call, pausing 4s to respect free tier RPM limit")
				time.Sleep(4 * time.Second)
			}
			return results, nil
		}

		// Check for rate limits to trigger cooldown
		if strings.Contains(strings.ToLower(err.Error()), "rate") ||
			strings.Contains(strings.ToLower(err.Error()), "limit") ||
			strings.Contains(strings.ToLower(err.Error()), "exhausted") ||
			strings.Contains(err.Error(), "429") {
			setCooldown(p, 5*time.Minute)
		}

		slog.Info("LLM: [FALLBACK] Provider failed, trying next...", "provider", p, "error", err)
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no valid llm providers configured (current: %s)", config.AppConfig.LLMProvider)
}

func extractWithGemini(ctx context.Context, apiKey, model, apiVersion, description string) ([]ProductResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("gemini api key is required")
	}

	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: apiKey,
		HTTPOptions: genai.HTTPOptions{
			APIVersion: apiVersion,
		},
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

	prompt := `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided description and reference URLs.

RULES:
1. Use the Reference URLs to disambiguate generic names (e.g. if description says "ftpd" but references point to "wu-ftpd", use "wu-ftpd").
2. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
3. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
4. If multiple products are mentioned, list them all.

EXAMPLES:
Input: "Vulnerability in Cisco IOS before 15.1"
Output: {"products": [{"vendor": "Cisco", "product": "IOS", "version": "< 15.1"}]}

Input: "The debug command in Sendmail is enabled"
Output: {"products": [{"vendor": "Sendmail", "product": "Sendmail", "version": null}]}

Description: ` + description
	if os.Getenv("LLM_DEBUG") == "true" {
		slog.Debug("LLM: [DEBUG] Gemini Prompt", "prompt", prompt)
	}

	result, err := client.Models.GenerateContent(ctx, model, genai.Text(prompt), config)
	if err != nil {
		return nil, err
	}

	if os.Getenv("LLM_DEBUG") == "true" {
		slog.Debug("LLM: [DEBUG] Gemini Raw Response", "response", result.Text())
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

	prompt := `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided description and reference URLs.

RULES:
1. Return results ONLY as a JSON object with a key "products" containing a list of objects.
2. Use the Reference URLs to disambiguate generic names (e.g. if description says "ftpd" but references point to "wu-ftpd", use "wu-ftpd").
3. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
4. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
5. If multiple products are mentioned, list them all.

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
]}

Description: ` + description

	if os.Getenv("LLM_DEBUG") == "true" {
		slog.Debug("LLM: [DEBUG] Ollama Prompt", "prompt", prompt)
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
		slog.Debug("LLM: [DEBUG] Ollama Raw Response", "response", ollamaResp.Response)
	}

	var res ExtractionResponse
	if err := json.Unmarshal([]byte(ollamaResp.Response), &res); err != nil {
		return nil, fmt.Errorf("failed to parse ollama json response: %w, text: %s", err, ollamaResp.Response)
	}

	return res.Products, nil
}

var timeSleep = time.Sleep

func extractWithArliAI(ctx context.Context, apiKey, model, endpoint, description string) ([]ProductResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("arliai api key is required")
	}

	systemPrompt := `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided description and reference URLs.

RULES:
1. Return results ONLY as a JSON object with a key "products" containing a list of objects.
2. Use the Reference URLs to disambiguate generic names (e.g. if description says "ftpd" but references point to "wu-ftpd", use "wu-ftpd").
3. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
4. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
5. If multiple products are mentioned, list them all.

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
		slog.Debug("LLM: [DEBUG] ArliAI System Prompt", "prompt", systemPrompt)
		slog.Debug("LLM: [DEBUG] ArliAI Description", "description", description)
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
			slog.Info("LLM: [RETRY] ArliAI hit limit, waiting before retry", "wait", wait, "attempt", i, "max_retries", 3)
			timeSleep(wait)
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
			slog.Debug("LLM: [DEBUG] ArliAI Raw Response", "response", content)
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
