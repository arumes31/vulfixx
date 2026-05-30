package worker

import (
	"context"
	"cve-tracker/internal/config"
	"cve-tracker/internal/llm"
	"cve-tracker/internal/models"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var defaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV30 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
		CvssMetricV2 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []models.CVEConfiguration `json:"configurations"`
}

type NVDCVEEntry struct {
	CVE NVDCVE `json:"cve"`
}

type NVDResponse struct {
	TotalResults    int           `json:"totalResults"`
	Vulnerabilities []NVDCVEEntry `json:"vulnerabilities"`
}

func (w *Worker) fetchCVEsPeriodically(ctx context.Context) {
	w.waitUntilNextRun(ctx, "nvd_sync", 1*time.Hour, 10*time.Second)
	w.fetchFromNVD(ctx)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.fetchFromNVD(ctx)
		}
	}
}

func (w *Worker) fetchFromNVD(ctx context.Context) {
	lastSync, err := w.getLastSyncTime(ctx)
	if err != nil {
		slog.Error("Worker: [ERROR] Failed to fetch last sync time", "error", err)
		return
	}
	if lastSync.IsZero() {
		startIndex := w.getBackfillProgress(ctx)
		if startIndex > 0 {
			slog.Info("Worker: Resuming NVD backfill", "start_index", startIndex)
		} else {
			slog.Info("Worker: No prior sync found — starting full NVD backfill...")
		}
		w.runFullSync(ctx, true, startIndex)
	} else {
		slog.Info("Worker: Incremental sync — fetching modified CVEs", "since", lastSync.Format(time.RFC3339))
		w.runFullSync(ctx, false, 0)
	}
}

func (w *Worker) runFullSync(ctx context.Context, isBackfill bool, startIndex int) {
	baseURL := defaultNVDBaseURL
	if envURL := os.Getenv("NVD_API_URL"); envURL != "" {
		parsed, err := url.Parse(envURL)
		if err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
			baseURL = parsed.String()
		}
	}

	params := url.Values{}
	endTime := time.Now().UTC()

	if !isBackfill {
		lastSync, err := w.getLastSyncTime(ctx)
		if err != nil {
			slog.Error("Worker: Error getting last sync time for incremental sync", "error", err)
			return
		}
		params.Set("lastModStartDate", lastSync.Format(time.RFC3339))
		params.Set("lastModEndDate", endTime.Format(time.RFC3339))
	}

	resultsPerPage := 500

	retryCount := 0
	const maxNVDRetries = 5

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		params.Set("resultsPerPage", fmt.Sprintf("%d", resultsPerPage))
		params.Set("startIndex", fmt.Sprintf("%d", startIndex))

		fullURL := baseURL + "?" + params.Encode()
		/* #nosec G704 */
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			slog.Error("Worker: Error creating NVD request", "error", err)
			return
		}

		if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := w.HTTP.Do(req)
		if err != nil {
			retryCount++
			slog.Error("Worker: Error fetching from NVD", "attempt", retryCount, "max_retries", maxNVDRetries, "error", err)
			if retryCount >= maxNVDRetries {
				slog.Error("Worker: Max NVD retries reached, aborting sync")
				return
			}
			backoff := time.Duration(math.Pow(2, float64(retryCount))) * time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			retryCount++
			if retryCount >= maxNVDRetries {
				slog.Error("Worker: Max NVD rate-limit retries reached, aborting sync")
				_ = resp.Body.Close()
				return
			}
			slog.Warn("Worker: Rate limited by NVD, waiting 30s...", "attempt", retryCount, "max_retries", maxNVDRetries)
			_ = resp.Body.Close()
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-timer.C:
				// continue after wait
			case <-ctx.Done():
				timer.Stop()
				return
			}
			continue
		}

		retryCount = 0 // reset on success

		if resp.StatusCode != http.StatusOK {
			/* #nosec G706 */
			slog.Error("Worker: NVD API returned error status", "status", resp.StatusCode)
			_ = resp.Body.Close()
			return
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			slog.Error("Worker: Error decoding NVD response JSON", "error", err)
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()

		if len(nvdResp.Vulnerabilities) == 0 {
			break
		}

		if err := w.upsertCVEs(ctx, nvdResp.Vulnerabilities, isBackfill); err != nil {
			slog.Error("Worker: NVD upsert failed, aborting sync", "error", err)
			return
		}

		slog.Info("Worker: [NVD] Successfully upserted batch of CVEs", "batch_size", len(nvdResp.Vulnerabilities), "processed", startIndex+len(nvdResp.Vulnerabilities), "total", nvdResp.TotalResults)

		if isBackfill {
			w.updateBackfillProgress(ctx, startIndex)
		}

		startIndex += resultsPerPage
		if startIndex >= nvdResp.TotalResults {
			break
		}

		// NVD recommends 0.6s delay with API Key, 6s without.
		nvdAPIDelay := 6 * time.Second
		if os.Getenv("NVD_API_KEY") != "" {
			nvdAPIDelay = 600 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nvdAPIDelay):
		}
	}

	w.updateLastSyncTime(ctx, endTime)
	if isBackfill {
		w.clearBackfillProgress(ctx)
	}
}

func parseNVDDate(dateStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		t, err := time.Parse(f, dateStr)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse date %q", dateStr)
}

func getCVSSMetric(metrics NVDCVE) (float64, string) {
	if len(metrics.Metrics.CvssMetricV31) > 0 {
		return metrics.Metrics.CvssMetricV31[0].CvssData.BaseScore, metrics.Metrics.CvssMetricV31[0].CvssData.VectorString
	}
	if len(metrics.Metrics.CvssMetricV30) > 0 {
		return metrics.Metrics.CvssMetricV30[0].CvssData.BaseScore, metrics.Metrics.CvssMetricV30[0].CvssData.VectorString
	}
	if len(metrics.Metrics.CvssMetricV2) > 0 {
		return metrics.Metrics.CvssMetricV2[0].CvssData.BaseScore, metrics.Metrics.CvssMetricV2[0].CvssData.VectorString
	}
	return 0, ""
}

func getCWEID(weaknesses []struct {
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}) string {
	for _, weak := range weaknesses {
		for _, d := range weak.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				return d.Value
			}
		}
	}
	return ""
}

func mapNVDEntryToModel(entry NVDCVEEntry) (models.CVE, error) {
	cve := entry.CVE

	description := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			description = d.Value
			break
		}
	}
	score, vector := getCVSSMetric(cve)
	cweID := getCWEID(cve.Weaknesses)

	var references []string
	exploitAvailable := false
	for _, ref := range cve.References {
		u, err := url.Parse(ref.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}

		// Check for exploit tags
		if slices.ContainsFunc(ref.Tags, func(tag string) bool {
			return strings.ToLower(tag) == "exploit"
		}) {
			exploitAvailable = true
		}

		// Also heuristic check on common exploit sites
		urlLower := strings.ToLower(ref.URL)
		if strings.Contains(urlLower, "exploit-db.com") ||
			strings.Contains(urlLower, "packetstormsecurity.com") ||
			strings.Contains(urlLower, "metasploit.com") ||
			strings.Contains(urlLower, "rapid7.com/db/modules") ||
			strings.Contains(urlLower, "github.com/") && (strings.Contains(urlLower, "/exploit") || strings.Contains(urlLower, "/poc")) {
			exploitAvailable = true
		}

		// Normalize
		u.Fragment = ""
		u.User = nil
		references = append(references, u.String())
	}

	pubDate, err := parseNVDDate(cve.Published)
	if err != nil {
		return models.CVE{}, fmt.Errorf("invalid published date for CVE %s: %w", cve.ID, err)
	}
	modDate, err := parseNVDDate(cve.LastModified)
	if err != nil {
		return models.CVE{}, fmt.Errorf("invalid lastModified date for CVE %s: %w", cve.ID, err)
	}

	return models.CVE{
		CVEID:            cve.ID,
		Description:      description,
		CVSSScore:        score,
		VectorString:     vector,
		CWEID:            cweID,
		References:       references,
		PublishedDate:    pubDate,
		UpdatedDate:      modDate,
		Configurations:   cve.Configurations,
		ExploitAvailable: exploitAvailable,
	}, nil
}
func (w *Worker) enrichCVEWithVendorProduct(ctx context.Context, model *models.CVE, skipLLM bool) (bool, error) {
	var vendor, product string
	llmSuccess := false

	if !skipLLM {
		llmCtx, cancel := context.WithTimeout(ctx, time.Duration(config.AppConfig.LLMTimeout)*time.Second)
		products, err := llm.ExtractVendorProduct(llmCtx, model.Description, model.References)
		cancel()
		if err == nil && len(products) > 0 {
			llmSuccess = true
			// Use the first one as primary
			vendor, product = products[0].Vendor, products[0].Product
			slog.Debug("Worker: LLM extraction success", "cve_id", model.CVEID, "products_found", len(products), "primary_vendor", vendor, "primary_product", product)

			// Add all to affected_products
			for _, p := range products {
				model.AddAffectedProduct(p.Vendor, p.Product, p.Version, true)
			}
		} else if err != nil {
			return false, err
		}
	} else {
		slog.Info("Worker: [NVD] Skipping LLM for CVE (heuristic mode active)", "cve_id", model.CVEID)
	}

	// Heuristic Fallback
	if vendor == "" || product == "" {
		hVendor, hProduct := model.GetDetectedProduct()
		if hVendor != "" && vendor == "" {
			vendor = hVendor
		}
		if hProduct != "" && product == "" {
			product = hProduct
		}
		if vendor != "" || product != "" {
			slog.Info("Worker: Heuristic fallback detection", "cve_id", model.CVEID, "vendor", vendor, "product", product)
		}
	}

	model.Vendor = vendor
	model.Product = product
	model.AffectedProducts = model.GetAffectedProducts()

	return llmSuccess, nil
}
func (w *Worker) executeCVEBatchUpsert(ctx context.Context, modelsToUpsert []models.CVE) ([]models.CVE, error) {
	if len(modelsToUpsert) == 0 {
		return nil, nil
	}

	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Worker: Error starting transaction for NVD upserts", "error", err)
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch := &pgx.Batch{}
	query := `
		INSERT INTO cves (cve_id, description, cvss_score, vector_string, cwe_id, "references", configurations, published_date, updated_date, vendor, product, affected_products, exploit_available)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (cve_id, published_date) DO UPDATE SET
			description = EXCLUDED.description,
			cvss_score = EXCLUDED.cvss_score,
			vector_string = EXCLUDED.vector_string,
			cwe_id = EXCLUDED.cwe_id,
			"references" = EXCLUDED."references",
			configurations = EXCLUDED.configurations,
			updated_date = EXCLUDED.updated_date,
			vendor = EXCLUDED.vendor,
			product = EXCLUDED.product,
			affected_products = EXCLUDED.affected_products,
			exploit_available = EXCLUDED.exploit_available,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id
	`

	for _, model := range modelsToUpsert {
		batch.Queue(query, model.CVEID, model.Description, model.CVSSScore, model.VectorString, model.CWEID, model.References, model.Configurations, model.PublishedDate, model.UpdatedDate, model.Vendor, model.Product, model.AffectedProducts, model.ExploitAvailable)
	}

	br := tx.SendBatch(ctx, batch)
	var successfulCVEs []models.CVE

	if br != nil {
		for i := 0; i < len(modelsToUpsert); i++ {
			var id int
			err := br.QueryRow().Scan(&id)
			if err != nil {
				_ = br.Close()
				slog.Error("Worker: Error executing batch item, rolling back transaction", "cve_id", modelsToUpsert[i].CVEID, "error", err)
				return nil, err
			}
			modelsToUpsert[i].ID = id
			successfulCVEs = append(successfulCVEs, modelsToUpsert[i])
		}
		if err := br.Close(); err != nil {
			slog.Error("Worker: Error closing batch results", "error", err)
			return nil, err
		}
	} else {
		slog.Warn("Worker: SendBatch returned nil (likely mock database). Falling back to individual inserts.")
		for i := range modelsToUpsert {
			var id int
			err := tx.QueryRow(ctx, query, modelsToUpsert[i].CVEID, modelsToUpsert[i].Description, modelsToUpsert[i].CVSSScore, modelsToUpsert[i].VectorString, modelsToUpsert[i].CWEID, modelsToUpsert[i].References, modelsToUpsert[i].Configurations, modelsToUpsert[i].PublishedDate, modelsToUpsert[i].UpdatedDate, modelsToUpsert[i].Vendor, modelsToUpsert[i].Product, modelsToUpsert[i].AffectedProducts, modelsToUpsert[i].ExploitAvailable).Scan(&id)
			if err != nil {
				slog.Error("Worker: Error upserting CVE in fallback, rolling back transaction", "cve_id", modelsToUpsert[i].CVEID, "error", err)
				return nil, err
			}
			modelsToUpsert[i].ID = id
			successfulCVEs = append(successfulCVEs, modelsToUpsert[i])
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Worker: Error committing NVD batch transaction", "error", err)
		return nil, err
	}

	return successfulCVEs, nil
}

func (w *Worker) upsertCVEs(ctx context.Context, entries []NVDCVEEntry, isBackfill bool) error {
	if len(entries) == 0 {
		return nil
	}

	slog.Info("Worker: [NVD] Preparing batch", "count", len(entries), "is_backfill", isBackfill)

	modelsToUpsert, err := w.prepareCVEModels(ctx, entries)
	if err != nil {
		return err
	}

	successfulCVEs, err := w.executeCVEBatchUpsert(ctx, modelsToUpsert)
	if err != nil {
		return err
	}

	slog.Info("Worker: [DATABASE CONFIRMED] Batch added successfully to DB", "batch_size", len(successfulCVEs))

	return w.handlePostUpsertActions(ctx, successfulCVEs, isBackfill)
}

func (w *Worker) prepareCVEModels(ctx context.Context, entries []NVDCVEEntry) ([]models.CVE, error) {
	var modelsToUpsert []models.CVE
	consecutiveLLMFailures := 0
	skipLLMForBatch := false
	totalInBatch := len(entries)

	for i, entry := range entries {
		select {
		case <-ctx.Done():
			slog.Info("Worker: Context cancelled, aborting NVD batch preparation.")
			return nil, ctx.Err()
		default:
		}

		slog.Info("Worker: [NVD] Processing CVE", "current", i+1, "total", totalInBatch, "cve_id", entry.CVE.ID)

		model, err := mapNVDEntryToModel(entry)
		if err != nil {
			slog.Warn("Worker: Error mapping NVD entry, skipping", "cve_id", entry.CVE.ID, "error", err)
			continue
		}

		llmSuccess, err := w.enrichCVEWithVendorProduct(ctx, &model, skipLLMForBatch)
		if err != nil {
			slog.Warn("Worker: LLM extraction failed", "cve_id", model.CVEID, "error", err)
			consecutiveLLMFailures++
			if consecutiveLLMFailures >= 5 {
				skipLLMForBatch = true
				slog.Error("Worker: TOO MANY CONSECUTIVE LLM FAILURES. Switching to HEURISTICS for the rest of this batch.", "consecutive_count", consecutiveLLMFailures, "batch_index", i)
			}
		} else if llmSuccess {
			consecutiveLLMFailures = 0
		}

		modelsToUpsert = append(modelsToUpsert, model)
	}
	return modelsToUpsert, nil
}

func (w *Worker) handlePostUpsertActions(ctx context.Context, successfulCVEs []models.CVE, isBackfill bool) error {
	for _, model := range successfulCVEs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case w.enrichmentQueue <- model.ID:
		}

		if !isBackfill {
			if err := w.enqueueAlertsForCVE(ctx, model); err != nil {
				slog.Error("Worker: Error enqueuing alerts for CVE", "cve_id", model.CVEID, "error", err)
			}
		}
	}
	return nil
}

func (w *Worker) getLastSyncTime(ctx context.Context) (time.Time, error) {
	var lastSync time.Time
	err := w.Pool.QueryRow(ctx, "SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").Scan(&lastSync)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return lastSync, nil
}

func (w *Worker) updateLastSyncTime(ctx context.Context, t time.Time) {
	_, err := w.Pool.Exec(ctx, `
		INSERT INTO worker_sync_stats (task_name, last_run)
		VALUES ('nvd_sync', $1)
		ON CONFLICT (task_name) DO UPDATE SET last_run = EXCLUDED.last_run
	`, t)
	if err != nil {
		slog.Error("Worker: Error updating sync stats", "error", err)
	}
}

func (w *Worker) getBackfillProgress(ctx context.Context) int {
	var val string
	err := w.Pool.QueryRow(ctx, "SELECT value FROM sync_state WHERE key = 'nvd_backfill_index'").Scan(&val)
	if err != nil {
		return 0
	}
	idx, _ := strconv.Atoi(val)
	return idx
}

func (w *Worker) updateBackfillProgress(ctx context.Context, idx int) {
	_, err := w.Pool.Exec(ctx, `
		INSERT INTO sync_state (key, value) VALUES ('nvd_backfill_index', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`, fmt.Sprintf("%d", idx))
	if err != nil {
		slog.Error("Worker: Error updating backfill progress", "index", idx, "error", err)
	}
}

func (w *Worker) clearBackfillProgress(ctx context.Context) {
	_, _ = w.Pool.Exec(ctx, "DELETE FROM sync_state WHERE key = 'nvd_backfill_index'")
}
