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
	"strconv"
	"strings"
	"sync"
	"time"

	"cve-tracker/internal/config"
	"cve-tracker/internal/db"
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

// defaultGeminiRPM is the free-tier requests-per-minute target used to pace
// Gemini calls. 15 RPM matches the default model's free-tier limit
// (gemini-3.1-flash-lite = 15 RPM / 500 RPD). Override via the GEMINI31FLASHLITE_RPM
// environment variable when using a model/tier with a different limit.
const defaultGeminiRPM = 15

// geminiPauseInterval returns how long to wait after a successful Gemini call so
// the steady-state request rate stays within the (free-tier) RPM limit.
func geminiPauseInterval() time.Duration {
	rpm := defaultGeminiRPM
	v := strings.TrimSpace(os.Getenv("GEMINI31FLASHLITE_RPM"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("GEMINI_RPM"))
	}
	if v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			rpm = parsed
		}
	}
	return time.Duration(int64(time.Minute) / int64(rpm))
}

// defaultGeminiRPD is the free-tier requests-per-day limit for the default model
// (gemini-3.1-flash-lite = 500 RPD). Override via the GEMINI31FLASHLITE_RPD environment
// variable; set it to 0 to disable daily quota tracking entirely.
const defaultGeminiRPD = 500

// geminiDailyLimit returns the configured Gemini requests-per-day ceiling. A
// value <= 0 disables tracking.
func geminiDailyLimit() int {
	limit := defaultGeminiRPD
	v := strings.TrimSpace(os.Getenv("GEMINI31FLASHLITE_RPD"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("GEMINI_RPD"))
	}
	if v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
	}
	return limit
}

// googleFailover describes a non-primary Google model used in the fallback
// chain after the primary Gemini model (gemini-3.1-flash-lite, provider
// "gemini31flashlite"). Each has its own rate limits and an independent Redis daily
// counter. `structured` selects the request style: Gemini models support
// structured output (extractWithGemini).
//
// Provider keys and defaults (override via the *_MODEL / *_RPM / *_RPD env vars):
//
//	gemini35flash      -> gemini-3.5-flash        15 RPM / 20   RPD (structured)
//	gemini3flash       -> gemini-3-flash-preview  15 RPM / 20   RPD (structured)
//	gemini31flashlite  -> gemini-3.1-flash-lite   15 RPM / 500  RPD (structured)
//
// A typical quality-first, quota-aware chain:
//
//	LLM_PROVIDER=gemini35flash,gemini3flash,gemini31flashlite,mistral,ollama
type googleFailover struct {
	model      string // Google API model id
	rpmEnv     string
	defRPM     int
	rpdEnv     string
	defRPD     int
	redisKey   string
	structured bool
}

// googleFailoverFor resolves a provider name to its spec, or ok=false if the
// name is not a Google failover provider. Model ids come from config so they
// stay overridable.
func googleFailoverFor(provider string) (googleFailover, bool) {
	switch provider {
	case "gemini35flash":
		return googleFailover{config.AppConfig.Gemini35Model, "GEMINI35FLASH_RPM", 15, "GEMINI35FLASH_RPD", 20, "gemini35flash", true}, true
	case "gemini3flash":
		return googleFailover{config.AppConfig.Gemini3Model, "GEMINI3FLASH_RPM", 15, "GEMINI3FLASH_RPD", 20, "gemini3flash", true}, true
	}
	return googleFailover{}, false
}

// googleFailoverPace returns the post-call pacing for a failover provider,
// honoring its RPM override env var.
func googleFailoverPace(f googleFailover) time.Duration {
	rpm := f.defRPM
	if v := strings.TrimSpace(os.Getenv(f.rpmEnv)); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			rpm = parsed
		}
	}
	return time.Duration(int64(time.Minute) / int64(rpm))
}

// googleFailoverDailyLimit returns a failover provider's requests-per-day
// ceiling from its RPD override env var (<= 0 disables tracking).
func googleFailoverDailyLimit(f googleFailover) int {
	limit := f.defRPD
	if v := strings.TrimSpace(os.Getenv(f.rpdEnv)); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
	}
	return limit
}

// googleFailoverRPDIncr increments today's (UTC) request counter for the given
// Redis key prefix, so each failover model tracks its daily quota independently.
// Package var so tests can substitute a fake.
var googleFailoverRPDIncr = func(ctx context.Context, keyPrefix string) (int64, error) {
	if db.RedisClient == nil {
		return 0, errors.New("redis client not initialized")
	}
	key := keyPrefix + ":rpd:" + time.Now().UTC().Format("2006-01-02")
	n, err := db.RedisClient.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		_ = db.RedisClient.Expire(ctx, key, 48*time.Hour).Err()
	}
	return n, nil
}

// googleFailoverQuotaExceeded increments and checks a failover provider's daily
// counter against its RPD limit. Fails open on Redis errors.
func googleFailoverQuotaExceeded(ctx context.Context, f googleFailover) bool {
	limit := googleFailoverDailyLimit(f)
	if limit <= 0 {
		return false
	}
	count, err := googleFailoverRPDIncr(ctx, f.redisKey)
	if err != nil {
		slog.Warn("LLM: could not check Google failover daily quota, allowing call", "model", f.model, "error", err)
		return false
	}
	if count > int64(limit) {
		slog.Warn("LLM: Google failover daily request quota reached", "model", f.model, "count", count, "limit", limit)
		return true
	}
	return false
}

// geminiRPDIncr atomically increments today's (UTC) Gemini request counter in
// Redis and returns the new total. The first increment of the day sets a TTL
// that comfortably outlives the UTC day so the counter self-resets. It is a
// package var so tests can substitute a fake. Shared across app instances via
// the common Redis key, so the ceiling is global, not per-process.
var geminiRPDIncr = func(ctx context.Context) (int64, error) {
	if db.RedisClient == nil {
		return 0, errors.New("redis client not initialized")
	}
	key := "gemini:rpd:" + time.Now().UTC().Format("2006-01-02")
	n, err := db.RedisClient.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		// First call of the day: expire well after midnight UTC so the key
		// disappears on its own without an explicit reset.
		_ = db.RedisClient.Expire(ctx, key, 48*time.Hour).Err()
	}
	return n, nil
}

// geminiDailyQuotaExceeded increments and checks the day's Gemini request
// counter against GEMINI_RPD. It fails open (returns false) on any Redis error
// so a cache outage never halts enrichment — at worst a few extra calls risk a
// 429, which the existing cooldown logic already absorbs.
func geminiDailyQuotaExceeded(ctx context.Context) bool {
	limit := geminiDailyLimit()
	if limit <= 0 {
		return false
	}
	count, err := geminiRPDIncr(ctx)
	if err != nil {
		slog.Warn("LLM: could not check Gemini daily quota, allowing call", "error", err)
		return false
	}
	if count > int64(limit) {
		slog.Warn("LLM: Gemini daily request quota reached", "count", count, "limit", limit)
		return true
	}
	return false
}

// durationUntilUTCMidnight returns the time remaining until the next UTC day
// boundary, used to cool Gemini down for the rest of the day once its daily
// quota is hit.
func durationUntilUTCMidnight() time.Duration {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
	return time.Until(next)
}

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

// ExtractVendorProduct chooses the appropriate provider(s) (Gemini, Ollama, or Mistral) to extract all vendor/product/version names.
// It supports a fallback chain if LLM_PROVIDER is a comma-separated list (e.g. "gemini35flash,gemini3flash,gemini31flashlite,mistral,ollama").
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

		// Enforce the Gemini free-tier daily request ceiling (RPD). Once hit,
		// cool Gemini down until the UTC day rolls over so the rest of this run
		// falls through to other providers instead of racking up 429s.
		if p == "gemini31flashlite" && geminiDailyQuotaExceeded(ctx) {
			setCooldown(p, durationUntilUTCMidnight())
			lastErr = fmt.Errorf("%w: gemini31flashlite daily request quota reached", ErrRateLimit)
			continue
		}
		// Google failover providers (gemini35flash, gemini3flash) each enforce
		// their own independent daily ceiling.
		gf, isFailover := googleFailoverFor(p)
		if isFailover && googleFailoverQuotaExceeded(ctx, gf) {
			setCooldown(p, durationUntilUTCMidnight())
			lastErr = fmt.Errorf("%w: %s daily request quota reached", ErrRateLimit, p)
			continue
		}

		var results []ProductResult
		var err error

		switch {
		case p == "gemini31flashlite":
			results, err = extractWithGemini(ctx, config.AppConfig.GeminiAPIKey, config.AppConfig.Gemini31LiteModel, config.AppConfig.GeminiAPIVersion, fullContext)
		case isFailover && gf.structured:
			// Gemini-family failover model (same API key): supports structured output.
			results, err = extractWithGemini(ctx, config.AppConfig.GeminiAPIKey, gf.model, config.AppConfig.GeminiAPIVersion, fullContext)
		case p == "ollama":
			results, err = extractWithOllama(ctx, config.AppConfig.LLMEndpoint, config.AppConfig.LLMModel, fullContext)
		case p == "mistral":
			results, err = extractWithMistral(ctx, config.AppConfig.MistralAPIKey, config.AppConfig.MistralModel, config.AppConfig.MistralEndpoint, fullContext)
		default:
			slog.Warn("LLM: [WARN] Unsupported provider in chain", "provider", p)
			continue
		}

		if err == nil {
			// Proactive rate limiting for the Google free tier. The semaphore is
			// still held here, so pausing also paces concurrent callers.
			var pause time.Duration
			if p == "gemini31flashlite" {
				pause = geminiPauseInterval()
			} else if isFailover {
				pause = googleFailoverPace(gf)
			}
			if pause > 0 {
				slog.Debug("LLM: successful Google call, pacing to respect free tier RPM", "provider", p, "pause", pause)
				select {
				case <-time.After(pause):
				case <-ctx.Done():
				}
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

// getSystemPrompt returns the shared extraction instructions used by every
// provider (Gemini, Ollama, Mistral). Keeping a single source of truth means an
// improvement to the rules or examples benefits all three models at once.
func getSystemPrompt() string {
	return `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided CVE description and reference URLs. Return ONLY a JSON object with a key "products" containing a list of objects, each with "vendor", "product", and "version".

RULES:
1. EXHAUSTIVITY: List EVERY distinct product mentioned as vulnerable. If a series of products is named (e.g., "Product A, B, and C"), output one entry per product. NEVER return an empty list if any product is mentioned.
2. DISAMBIGUATE: Use Reference URLs to identify specific product names if the description is generic (e.g., "ftpd" -> "wu-ftpd"). 
3. "AS USED IN": When a vulnerability is in a component "as used in" a host product (e.g., "WebKit as used in Safari"), extract the host product (Safari) as the affected software.
4. PLATFORMS: If a vulnerability is specific to a platform (e.g., "on Windows", "for Android", "on Mac OS X"), extract that platform as an additional affected product.
5. ALIASES (aka): If a product has an alias (e.g., "Dashboard (aka Horizon)"), prefer the most distinct name ("Horizon"). 
6. PLUGINS: For plugins/themes/extensions, the product is the extension name and the vendor is its author. Do NOT report the host platform (WordPress, Drupal) as the vendor unless the core platform is also vulnerable.
7. VERSIONING: Format versions strictly: "before"/"prior to" X -> "< X"; "through" X or "X and earlier" -> "<= X"; "X through Y" -> "X through Y"; "from X before Y" -> ">= X, < Y". Use null if no version is given.
8. HARDWARE: Treat a device and its firmware as ONE product. Use the device model name.
9. NEGATIVE CONSTRAINTS: NEVER extract vulnerability types (XSS, SQLi), function names (e.g., "vfprintf"), file paths (e.g., "config.php"), or CVE IDs as products. Use exact names from the text; do not hallucinate.

EXAMPLES:
Input: "Buffer overflow in Quick Heal Total Security 10.1, Internet Security 10.1, and AntiVirus Pro 10.1"
Output: {"products": [{"vendor": "Quick Heal", "product": "Total Security", "version": "10.1"}, {"vendor": "Quick Heal", "product": "Internet Security", "version": "10.1"}, {"vendor": "Quick Heal", "product": "AntiVirus Pro", "version": "10.1"}]}

Input: "Vulnerability in WebKit, as used in Apple Safari before 4.0.5 on Windows"
Output: {"products": [{"vendor": "Apple", "product": "Safari", "version": "< 4.0.5"}, {"vendor": "Microsoft", "product": "Windows", "version": null}]}

Input: "MediaTek keyInstall (aka keymgr) allows escalation..."
Output: {"products": [{"vendor": "MediaTek", "product": "keymgr", "version": null}]}`
}

// getOllamaSystemPrompt returns the extraction instructions for the local model.
// Empirically the small local model (phi3, ~3.8B) is highly prompt-sensitive:
// the richer shared prompt used for Gemini/Mistral causes over-extraction
// (function names, empty entries) and lowers accuracy, so the local model keeps
// this leaner, well-tested prompt instead. See bench notes in run_test.sh.
func getOllamaSystemPrompt() string {
	return `Extract ALL affected software/hardware vendor(s), product name(s), and version(s) from the provided description and reference URLs.

RULES:
1. Return results ONLY as a JSON object with a key "products" containing a list of objects.
2. Use the Reference URLs to disambiguate generic names (e.g. if description says "ftpd" but references point to "wu-ftpd", use "wu-ftpd").
3. If a version is described as "prior to", "before", "through", or "and earlier", format it as a range (e.g. "< 1.2.3" or "<= 4.5").
4. DO NOT hallucinate modern product names for legacy software. Use the exact names from the text.
5. If multiple products are mentioned, list them all.
6. Treat device and firmware as ONE product.

EXAMPLES:
Input: "Vulnerability in Cisco IOS before 15.1"
Output: {"products": [{"vendor": "Cisco", "product": "IOS", "version": "< 15.1"}]}

Input: "The debug command in Sendmail is enabled"
Output: {"products": [{"vendor": "Sendmail", "product": "Sendmail", "version": null}]}

Input: "MediaTek keyInstall local escalation of privilege affects various SoCs"
Output: {"products": [{"vendor": "MediaTek", "product": "keyInstall", "version": null}]}`
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

	prompt := getSystemPrompt() + "\n\nDescription: " + description
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

	prompt := getOllamaSystemPrompt() + "\n\nDescription: " + description

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

func extractWithMistral(ctx context.Context, apiKey, model, endpoint, description string) ([]ProductResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("mistral api key is required")
	}

	defer func() {
		// Pace requests to Mistral (free tier allows ~1 request/second).
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	}()

	systemPrompt := getSystemPrompt()

	if os.Getenv("LLM_DEBUG") == "true" {
		slog.Debug("LLM: [DEBUG] Mistral System Prompt", "prompt", systemPrompt)
		slog.Debug("LLM: [DEBUG] Mistral Description", "description", description)
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
			slog.Info("LLM: [RETRY] Mistral hit limit, waiting before retry", "wait", wait, "attempt", i, "max_retries", 3)
			timeSleep(wait)
		}

		products, err, shouldRetry := func() ([]ProductResult, error, bool) {
			resp, err := client.Do(req)
			if err != nil {
				return nil, err, false
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 || resp.StatusCode == 429 {
				body, _ := io.ReadAll(resp.Body)
				if strings.Contains(string(body), "parallel") || strings.Contains(string(body), "rate") || strings.Contains(string(body), "limit") {
					// Reset request body for retry if possible (re-create request)
					req, _ = http.NewRequestWithContext(ctx, "POST", endpoint+"/chat/completions", bytes.NewBuffer(jsonData))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer "+apiKey)
					return nil, ErrRateLimit, true
				}
				return nil, fmt.Errorf("mistral api error (status %d): %s", resp.StatusCode, string(body)), false
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("mistral api error (status %d): %s", resp.StatusCode, string(body)), false
			}

			var chatResp struct {
				Choices []struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				} `json:"choices"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
				return nil, err, false
			}

			if len(chatResp.Choices) == 0 {
				return nil, fmt.Errorf("mistral returned no choices"), false
			}

			content := chatResp.Choices[0].Message.Content
			if os.Getenv("LLM_DEBUG") == "true" {
				slog.Debug("LLM: [DEBUG] Mistral Raw Response", "response", content)
			}

			// Clean JSON if the model wrapped it in markdown code blocks
			content = strings.TrimPrefix(content, "```json")
			content = strings.TrimPrefix(content, "```")
			content = strings.TrimSuffix(content, "```")
			content = strings.TrimSpace(content)

			var res ExtractionResponse
			if err := json.Unmarshal([]byte(content), &res); err != nil {
				return nil, fmt.Errorf("failed to parse mistral json: %w (content: %s)", err, content), false
			}

			return res.Products, nil, false
		}()

		if !shouldRetry {
			return products, err
		}
		lastErr = err
	}

	return nil, lastErr
}
