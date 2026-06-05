// Command improve_llm improves the local Ollama CVE vendor/product extraction
// model. It samples random real CVEs from the local NVD mirror (data/nvd),
// derives ground-truth vendor/product pairs from their CPE configurations,
// and then:
//
//  1. baselines the current Ollama model + system prompt on a held-out eval set,
//  2. optionally compares candidate base models (MODE=basemodels),
//  3. runs a one-by-one improvement loop (MODE=improve, default) that inspects
//     each training CVE, collects failures, and periodically asks a teacher LLM
//     (Mistral/Gemini) to refine the system prompt — keeping a candidate only if
//     it improves the held-out eval score (greedy hill-climb with validation, so
//     we don't overfit to individual CVEs).
//
// Crucially the harness calls Ollama DIRECTLY with a candidate system prompt it
// holds as data, so prompt changes are measured WITHOUT recompiling the llm
// package. The winning prompt/base model are written out at the end (to
// ollama_prompt.winner.txt and printed) for application to client.go and the
// Modelfile.
//
// Env:
//
//	MODE           baseline | basemodels | improve   (default improve)
//	EVAL_N         held-out eval set size            (default 120)
//	TRAIN_N        training CVEs to process one-by-one (default 1000, capped)
//	BATCH          failures to accumulate before a teacher refinement (default 20)
//	TEACHER        mistral | gemini                  (default mistral)
//	BASE_MODEL     ollama base model to test         (default qwen2.5:3b)
//	LLM_ENDPOINT   ollama endpoint                   (default http://localhost:11434)
//	SAMPLE_SEED    RNG seed for reproducible sampling (default 42)
package main

import (
	"bytes"
	"cve-tracker/internal/config"
	"cve-tracker/internal/llm"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type truthProduct struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

type evalCase struct {
	ID    string
	Desc  string
	Refs  []string
	Truth []truthProduct
}

// --- NVD parsing (local mirror, same shape as the NVD 2.0 API) ---

type nvdFile struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			VulnStatus   string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Configurations []models.CVEConfiguration `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	if err := config.LoadConfig(); err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	mode := env("MODE", "improve")
	provider := env("PROVIDER", "ollama") // ollama | mistral | gemini
	evalN := envInt("EVAL_N", 120)
	trainN := envInt("TRAIN_N", 1000)
	batch := envInt("BATCH", 20)
	teacher := env("TEACHER", "mistral")
	baseModel := env("BASE_MODEL", "qwen2.5:3b")
	endpoint := env("LLM_ENDPOINT", "http://localhost:11434")
	seed := int64(envInt("SAMPLE_SEED", 42))

	fmt.Printf("=== improve_llm: mode=%s provider=%s eval=%d train=%d batch=%d teacher=%s base=%s ===\n",
		mode, provider, evalN, trainN, batch, teacher, baseModel)

	// Sample a large pool once, deterministically, then split eval/train.
	pool := sampleCases(seed, evalN+trainN+200)
	fmt.Printf("Sampled %d usable CVEs from data/nvd (with CPE truth + mention filter)\n", len(pool))
	if len(pool) < evalN+10 {
		fmt.Println("Not enough usable CVEs sampled; aborting.")
		os.Exit(1)
	}
	evalSet := pool[:evalN]
	trainSet := pool[evalN:]
	if len(trainSet) > trainN {
		trainSet = trainSet[:trainN]
	}

	curPrompt := currentPrompt(provider)
	// PROMPT_FILE lets us evaluate a candidate prompt (e.g. a winner produced by a
	// prior run) instead of the one currently in client.go — used to cross-validate
	// a prompt tuned on one provider against another before adopting it.
	if pf := os.Getenv("PROMPT_FILE"); pf != "" {
		if b, err := os.ReadFile(pf); err == nil {
			curPrompt = string(b)
			fmt.Printf("Loaded prompt from %s\n", pf)
		} else {
			fmt.Printf("warn: could not read PROMPT_FILE %s: %v\n", pf, err)
		}
	}
	fmt.Printf("Current %s prompt: %d chars\n", provider, len(curPrompt))

	// For ollama, mdl is the base model name; for mistral/gemini the model is
	// taken from config and this is just a label.
	mdl := baseModel
	switch provider {
	case "mistral":
		mdl = config.AppConfig.MistralModel
	case "gemini":
		mdl = config.AppConfig.GeminiModel
	case "gemma":
		mdl = config.AppConfig.GemmaModel
	case "gemma2":
		mdl = config.AppConfig.Gemma2Model
	}

	switch mode {
	case "baseline":
		full, rec := evalPrompt(provider, endpoint, mdl, curPrompt, evalSet, true)
		fmt.Printf("\nBASELINE %s/%s: full-match=%.1f%% avg-recall=%.1f%% over %d cases\n",
			provider, mdl, full*100, rec*100, len(evalSet))

	case "basemodels":
		candidates := strings.Split(env("BASE_MODELS", "qwen2.5:3b,llama3.2:3b,gemma2:2b"), ",")
		type res struct {
			model string
			full  float64
			rec   float64
		}
		var results []res
		for _, m := range candidates {
			m = strings.TrimSpace(m)
			fmt.Printf("\n--- evaluating base model %s ---\n", m)
			full, rec := evalPrompt("ollama", endpoint, m, curPrompt, evalSet, false)
			results = append(results, res{m, full, rec})
			fmt.Printf("  %s: full-match=%.1f%% avg-recall=%.1f%%\n", m, full*100, rec*100)
		}
		sort.Slice(results, func(i, j int) bool { return results[i].full > results[j].full })
		fmt.Printf("\n=== base model ranking (by full-match on %d cases) ===\n", len(evalSet))
		for _, r := range results {
			fmt.Printf("  %-16s full=%.1f%% recall=%.1f%%\n", r.model, r.full*100, r.rec*100)
		}

	default: // improve
		improveLoop(provider, endpoint, mdl, curPrompt, evalSet, trainSet, batch, teacher)
	}
}

// improveLoop processes training CVEs one-by-one, collecting failures and
// periodically asking the teacher to refine the prompt. A refined prompt is
// adopted only if it beats the current best on the held-out eval set.
func improveLoop(provider, endpoint, mdl, startPrompt string, evalSet, trainSet []evalCase, batch int, teacher string) {
	bestPrompt := startPrompt
	bestFull, bestRec := evalPrompt(provider, endpoint, mdl, bestPrompt, evalSet, false)
	baseFull := bestFull
	fmt.Printf("\nBASELINE %s/%s: full-match=%.1f%% avg-recall=%.1f%% (eval n=%d)\n",
		provider, mdl, bestFull*100, bestRec*100, len(evalSet))

	winnerFile := provider + "_prompt.winner.txt"
	var failures []evalCase
	adopted := 0

	for i, c := range trainSet {
		preds := predict(provider, endpoint, mdl, bestPrompt, c.Desc)
		rec, _ := scoreCase(c.Truth, preds)
		status := "PASS"
		if rec < 0.999 {
			status = "FAIL"
			failures = append(failures, c)
		}
		fmt.Printf("[%d/%d] %s  r=%.2f  %s (%d truth, %d pred)\n",
			i+1, len(trainSet), c.ID, rec, status, len(c.Truth), len(preds))

		if len(failures) >= batch {
			fmt.Printf("  >> %d failures collected; asking %s for a prompt refinement...\n", len(failures), teacher)
			cand, err := refinePrompt(teacher, bestPrompt, failures)
			failures = nil
			if err != nil {
				fmt.Printf("  >> teacher error: %v (keeping current prompt)\n", err)
				continue
			}
			if cand == "" || cand == bestPrompt {
				fmt.Println("  >> teacher returned no usable change")
				continue
			}
			candFull, candRec := evalPrompt(provider, endpoint, mdl, cand, evalSet, false)
			fmt.Printf("  >> candidate: full=%.1f%% recall=%.1f%%  (best: full=%.1f%% recall=%.1f%%)\n",
				candFull*100, candRec*100, bestFull*100, bestRec*100)
			// Adopt if full-match improves, or equal full-match with better recall.
			if candFull > bestFull+0.0001 || (candFull >= bestFull-0.0001 && candRec > bestRec+0.0001) {
				bestPrompt, bestFull, bestRec = cand, candFull, candRec
				adopted++
				fmt.Printf("  >> ADOPTED refinement #%d (new best full=%.1f%%)\n", adopted, bestFull*100)
				if err := os.WriteFile(winnerFile, []byte(bestPrompt), 0600); err != nil {
					fmt.Printf("  >> warn: could not checkpoint winner: %v\n", err)
				}
			} else {
				fmt.Println("  >> rejected (no held-out improvement)")
			}
		}
	}

	fmt.Printf("\n=== improvement complete (%s) ===\n", provider)
	fmt.Printf("processed %d CVEs, adopted %d refinements\n", len(trainSet), adopted)
	fmt.Printf("FINAL eval: full-match=%.1f%% avg-recall=%.1f%% (baseline was full=%.1f%%)\n",
		bestFull*100, bestRec*100, baseFull*100)
	if bestPrompt != startPrompt {
		if err := os.WriteFile(winnerFile, []byte(bestPrompt), 0600); err != nil {
			fmt.Printf("warn: could not write winner: %v\n", err)
		} else {
			fmt.Printf("winning prompt written to %s\n", winnerFile)
		}
	} else {
		fmt.Println("no prompt change beat the baseline on the held-out set")
	}
}

// evalPrompt scores a (model, prompt) pair over a set of cases.
// Returns (fullMatchRate, avgRecall). fullMatch = recall==1.0 for that CVE.
func evalPrompt(provider, endpoint, mdl, prompt string, cases []evalCase, verbose bool) (float64, float64) {
	full, recSum := 0, 0.0
	for i, c := range cases {
		preds := predict(provider, endpoint, mdl, prompt, c.Desc)
		rec, _ := scoreCase(c.Truth, preds)
		recSum += rec
		if rec >= 0.999 {
			full++
		}
		if verbose {
			fmt.Printf("  eval[%d/%d] %s r=%.2f\n", i+1, len(cases), c.ID, rec)
		}
	}
	n := float64(len(cases))
	if n == 0 {
		return 0, 0
	}
	return float64(full) / n, recSum / n
}

// --- prediction routing ---

// predict runs one extraction for the given provider with a candidate prompt.
func predict(provider, endpoint, mdl, prompt, desc string) []llm.ProductResult {
	switch provider {
	case "mistral":
		return callMistralExtract(prompt, desc)
	case "gemini":
		return callGeminiExtract(prompt, desc)
	case "gemma", "gemma2":
		// mdl already resolved to the Gemma model id; Gemma needs a schema-less
		// request and tolerant parsing (verbose output wrapped in ```json).
		return callGemmaExtract(mdl, prompt, desc)
	default:
		return callOllama(endpoint, mdl, prompt, desc)
	}
}

// --- Ollama direct call ---

func callOllama(endpoint, mdl, systemPrompt, desc string) []llm.ProductResult {
	prompt := systemPrompt + "\n\nDescription: " + desc
	payload := map[string]interface{}{
		"model":  mdl,
		"prompt": prompt,
		"stream": false,
		"format": "json",
		"options": map[string]interface{}{
			"temperature": 0.0,
			"num_predict": 512,
			"num_ctx":     8192,
		},
	}
	jsonData, _ := json.Marshal(payload)
	to := time.Duration(config.AppConfig.LLMTimeout) * time.Second
	if to <= 0 {
		to = 240 * time.Second
	}
	client := &http.Client{Timeout: to}
	resp, err := client.Post(endpoint+"/api/generate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var gen struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gen); err != nil {
		return nil
	}
	return parseProducts(gen.Response)
}

func parseProducts(s string) []llm.ProductResult {
	s = strings.TrimSpace(s)
	// Ollama with format:json returns a JSON object; tolerate a few shapes.
	var obj struct {
		Products []llm.ProductResult `json:"products"`
	}
	if err := json.Unmarshal([]byte(s), &obj); err == nil && len(obj.Products) > 0 {
		return obj.Products
	}
	var arr []llm.ProductResult
	if err := json.Unmarshal([]byte(s), &arr); err == nil {
		return arr
	}
	return nil
}

// --- scoring (mirrors cmd/test_llms with the mention filter) ---

func scoreCase(truth []truthProduct, preds []llm.ProductResult) (recall, precision float64) {
	if len(truth) == 0 {
		return 1, 1 // nothing to find; treat as trivially satisfied
	}
	hit := 0
	for _, t := range truth {
		for _, p := range preds {
			if productMatch(t.Product, p.Product) || productMatch(t.Vendor, p.Product) || productMatch(t.Product, p.Vendor) {
				hit++
				break
			}
		}
	}
	recall = float64(hit) / float64(len(truth))
	if len(preds) > 0 {
		pHit := 0
		for _, p := range preds {
			for _, t := range truth {
				if productMatch(t.Product, p.Product) || productMatch(t.Vendor, p.Product) || productMatch(t.Product, p.Vendor) {
					pHit++
					break
				}
			}
		}
		precision = float64(pHit) / float64(len(preds))
	}
	return recall, precision
}

var nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)

func tokens(s string) []string {
	s = strings.ToLower(s)
	s = nonAlnumRe.ReplaceAllString(s, " ")
	var out []string
	for _, t := range strings.Fields(s) {
		switch t {
		case "the", "a", "an", "for", "and", "of", "software", "project",
			"plugin", "module", "server", "system", "framework", "library":
			continue
		}
		out = append(out, t)
	}
	return out
}

func productMatch(truth, pred string) bool {
	tt, pt := tokens(truth), tokens(pred)
	if len(tt) == 0 || len(pt) == 0 {
		return false
	}
	tset := map[string]bool{}
	for _, t := range tt {
		tset[t] = true
	}
	pset := map[string]bool{}
	for _, t := range pt {
		pset[t] = true
	}
	inter := 0
	for t := range tset {
		if pset[t] {
			inter++
		}
	}
	if inter == 0 {
		return false
	}
	if inter == len(tset) || inter == len(pset) {
		return true
	}
	union := len(tset) + len(pset) - inter
	return float64(inter)/float64(union) >= 0.5
}

// distroVendors repackage upstream software; their CPE entries are noise for
// description-based extraction, so we drop them from truth.
var distroVendors = map[string]bool{
	"fedoraproject": true, "fedora": true, "debian": true, "canonical": true,
	"ubuntu": true, "opensuse": true, "suse": true, "redhat": true, "red hat": true,
	"oracle": true, "novell": true, "mandriva": true, "gentoo": true, "slackware": true,
}

// mentioned reports whether the truth product's longest distinctive token
// appears in the description (so we only score things actually stated).
func mentioned(p truthProduct, desc string) bool {
	dl := strings.ToLower(desc)
	longest := ""
	for _, tok := range tokens(p.Product) {
		if len(tok) > len(longest) {
			longest = tok
		}
	}
	if longest == "" || len(longest) < 3 {
		return false
	}
	return strings.Contains(dl, longest)
}

func filterTruth(truth []truthProduct, desc string) []truthProduct {
	var out []truthProduct
	seen := map[string]bool{}
	for _, t := range truth {
		if distroVendors[strings.ToLower(t.Vendor)] {
			continue
		}
		if !mentioned(t, desc) {
			continue
		}
		key := strings.ToLower(t.Vendor + ":" + t.Product)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// --- sampling from data/nvd ---

func sampleCases(seed int64, want int) []evalCase {
	files, _ := filepath.Glob("data/nvd/*.json")
	if len(files) == 0 {
		fmt.Println("no data/nvd/*.json files found")
		os.Exit(1)
	}
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(files), func(i, j int) { files[i], files[j] = files[j], files[i] })

	var cases []evalCase
	for _, f := range files {
		if len(cases) >= want {
			break
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var nf nvdFile
		if err := json.Unmarshal(raw, &nf); err != nil {
			continue
		}
		// shuffle records within the file for diversity
		recs := nf.Vulnerabilities
		rng.Shuffle(len(recs), func(i, j int) { recs[i], recs[j] = recs[j], recs[i] })
		for _, v := range recs {
			if len(cases) >= want {
				break
			}
			c := v.CVE
			if strings.HasPrefix(strings.ToUpper(c.VulnStatus), "REJECT") {
				continue
			}
			desc := ""
			for _, d := range c.Descriptions {
				if d.Lang == "en" {
					desc = d.Value
					break
				}
			}
			if desc == "" || strings.Contains(desc, "** REJECT **") || strings.HasPrefix(desc, "Rejected reason") {
				continue
			}
			cve := models.CVE{Configurations: models.CVEConfigurations(c.Configurations)}
			affected := cve.GetAffectedProducts()
			if len(affected) == 0 {
				continue
			}
			var truth []truthProduct
			for _, a := range affected {
				if a.Vendor == "" || a.Product == "" {
					continue
				}
				truth = append(truth, truthProduct{Vendor: a.Vendor, Product: a.Product})
			}
			truth = filterTruth(truth, desc)
			if len(truth) == 0 {
				continue
			}
			var refs []string
			for _, r := range c.References {
				if r.URL != "" {
					refs = append(refs, r.URL)
				}
				if len(refs) >= 4 {
					break
				}
			}
			cases = append(cases, evalCase{ID: c.ID, Desc: desc, Refs: refs, Truth: truth})
		}
	}
	return cases
}

// --- current prompt extraction + teacher refinement ---

func currentPrompt(provider string) string {
	raw, err := os.ReadFile("internal/llm/client.go")
	if err != nil {
		return ""
	}
	fn := "getSystemPrompt"
	if provider == "ollama" {
		fn = "getOllamaSystemPrompt"
	}
	re := regexp.MustCompile("(?s)func " + fn + "\\(\\) string \\{\\s*return `(.*?)`")
	m := re.FindStringSubmatch(string(raw))
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// callMistralExtract runs a vendor/product extraction via the Mistral chat API
// using `systemPrompt` as the system message (so prompt == data, no recompile).
func callMistralExtract(systemPrompt, desc string) []llm.ProductResult {
	payload := map[string]interface{}{
		"model": config.AppConfig.MistralModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": "Description: " + desc},
		},
		"temperature":     0,
		"response_format": map[string]string{"type": "json_object"},
	}
	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", config.AppConfig.MistralEndpoint+"/chat/completions", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.AppConfig.MistralAPIKey)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		time.Sleep(3 * time.Second)
		return nil
	}
	if resp.StatusCode != 200 {
		return nil
	}
	var cr struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil || len(cr.Choices) == 0 {
		return nil
	}
	time.Sleep(400 * time.Millisecond) // gentle pacing for rate limits
	return parseProducts(cr.Choices[0].Message.Content)
}

// callGeminiExtract runs extraction via Gemini with `systemPrompt` as the
// system instruction.
func callGeminiExtract(systemPrompt, desc string) []llm.ProductResult {
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		"https://generativelanguage.googleapis.com/v1beta",
		config.AppConfig.GeminiModel, config.AppConfig.GeminiAPIKey)
	payload := map[string]interface{}{
		"system_instruction": map[string]interface{}{
			"parts": []map[string]string{{"text": systemPrompt}},
		},
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": "Description: " + desc}}},
		},
		"generationConfig": map[string]interface{}{
			"temperature":      0,
			"responseMimeType": "application/json",
		},
	}
	jsonData, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var gr struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil ||
		len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return nil
	}
	return parseProducts(gr.Candidates[0].Content.Parts[0].Text)
}

// callGemmaExtract calls a Gemma model on the Google API. Gemma does NOT support
// system_instruction or structured output, so the prompt is folded into a single
// user turn and the (often verbose) text response is parsed tolerantly.
func callGemmaExtract(model, systemPrompt, desc string) []llm.ProductResult {
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		"https://generativelanguage.googleapis.com/v1beta",
		model, config.AppConfig.GeminiAPIKey)
	prompt := systemPrompt + "\n\nReturn ONLY the JSON object, no markdown fences or commentary.\n\nDescription: " + desc
	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{"temperature": 0},
	}
	jsonData, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		time.Sleep(4 * time.Second)
		return nil
	}
	if resp.StatusCode != 200 {
		return nil
	}
	var gr struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil ||
		len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return nil
	}
	// Pace to respect the Gemma free-tier limit (default 15 RPM = 4s). Override
	// with GEMMA_PACE_MS for paid tiers.
	pace := 4200 * time.Millisecond
	if v := os.Getenv("GEMMA_PACE_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			pace = time.Duration(ms) * time.Millisecond
		}
	}
	time.Sleep(pace)
	return parseGemmaProducts(gr.Candidates[0].Content.Parts[0].Text)
}

// parseGemmaProducts tolerantly extracts {"products":[...]} from verbose Gemma
// output: it prefers fenced ```json blocks, then string-aware balanced {...}
// spans containing a "products" key.
func parseGemmaProducts(raw string) []llm.ProductResult {
	// 1. fenced blocks
	for _, m := range gemmaFenceRe.FindAllStringSubmatch(raw, -1) {
		if strings.Contains(m[1], "\"products\"") {
			if p := parseProducts(m[1]); len(p) > 0 || strings.Contains(m[1], "[]") {
				return p
			}
		}
	}
	// 2. whole string
	if p := parseProducts(raw); p != nil {
		return p
	}
	// 3. balanced {...} spans containing "products"
	depth, start := 0, -1
	inStr, esc := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '{':
			if depth == 0 {
				start = i
			}
			depth++
		case c == '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					cand := raw[start : i+1]
					if strings.Contains(cand, "\"products\"") {
						if p := parseProducts(cand); p != nil {
							return p
						}
					}
					start = -1
				}
			}
		}
	}
	return nil
}

var gemmaFenceRe = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```")

func refinePrompt(teacher, current string, failures []evalCase) (string, error) {
	var sb strings.Builder
	for i, f := range failures {
		if i >= 12 {
			break
		}
		tj, _ := json.Marshal(f.Truth)
		fmt.Fprintf(&sb, "CVE %s\nDescription: %s\nExpected products (vendor/product): %s\n\n", f.ID, trim(f.Desc, 500), string(tj))
	}
	meta := fmt.Sprintf(`You are an expert prompt engineer tuning a SMALL local LLM (3B params) that extracts affected vendor/product/version from CVE descriptions and returns JSON {"products":[{"vendor","product","version"}]}.

Here is the CURRENT system prompt:
---
%s
---

The model FAILED on these real CVEs (it missed or mis-named the expected products):
%s
Propose an IMPROVED system prompt. Rules:
- Keep it CONCISE; small models degrade with long prompts. Prefer adding/clarifying a general RULE over piling on examples.
- Add at most ONE new short example only if it teaches a general pattern.
- Do NOT overfit to specific vendor names from the failures.
- Keep the JSON output contract and existing good rules intact.
- Return ONLY the full new system prompt text, no markdown fences, no commentary.`, current, sb.String())

	switch teacher {
	case "gemini":
		return callGemini(meta)
	default:
		return callMistral(meta)
	}
}

func trim(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

func cleanPrompt(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.ReplaceAll(s, "`", "'") // backticks would break the Go raw-string when applied
	return strings.TrimSpace(s)
}

func callMistral(prompt string) (string, error) {
	payload := map[string]interface{}{
		"model":       config.AppConfig.MistralModel,
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"temperature": 0.2,
	}
	jsonData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", config.AppConfig.MistralEndpoint+"/chat/completions", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.AppConfig.MistralAPIKey)
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("mistral status %d", resp.StatusCode)
	}
	var cr struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", err
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("no mistral response")
	}
	return cleanPrompt(cr.Choices[0].Message.Content), nil
}

func callGemini(prompt string) (string, error) {
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		"https://generativelanguage.googleapis.com/v1beta",
		config.AppConfig.GeminiModel, config.AppConfig.GeminiAPIKey)
	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{"temperature": 0.2},
	}
	jsonData, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("gemini status %d", resp.StatusCode)
	}
	var gr struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", err
	}
	if len(gr.Candidates) == 0 || len(gr.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no gemini response")
	}
	return cleanPrompt(gr.Candidates[0].Content.Parts[0].Text), nil
}
