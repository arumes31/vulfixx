package worker

import (
	"context"
	"cve-tracker/internal/config"
	"cve-tracker/internal/llm"
	"cve-tracker/internal/models"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
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
		log.Printf("Worker: [ERROR] Failed to fetch last sync time: %v", err)
		return
	}
	if lastSync.IsZero() {
		startIndex := w.getBackfillProgress(ctx)
		if startIndex > 0 {
			log.Printf("Worker: Resuming NVD backfill from index %d...", startIndex)
		} else {
			log.Println("Worker: No prior sync found — starting full NVD backfill...")
		}
		w.runFullSync(ctx, true, startIndex)
	} else {
		log.Printf("Worker: Incremental sync — fetching CVEs modified since %s", lastSync.Format(time.RFC3339))
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
			log.Printf("Worker: Error getting last sync time: %v", err)
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
			log.Printf("Worker: Error creating NVD request: %v", err)
			return
		}

		if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := w.HTTP.Do(req)
		if err != nil {
			retryCount++
			log.Printf("Worker: Error fetching from NVD (attempt %d/%d): %v", retryCount, maxNVDRetries, err)
			if retryCount >= maxNVDRetries {
				log.Printf("Worker: Max NVD retries reached, aborting sync")
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
				log.Printf("Worker: Max NVD rate-limit retries reached, aborting sync")
				_ = resp.Body.Close()
				return
			}
			log.Printf("Worker: Rate limited by NVD (attempt %d/%d), waiting 30s...", retryCount, maxNVDRetries)
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
			log.Printf("Worker: NVD API returned status %d", resp.StatusCode)
			_ = resp.Body.Close()
			return
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			log.Printf("Worker: Error decoding NVD response: %v", err)
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()

		if len(nvdResp.Vulnerabilities) == 0 {
			break
		}

		w.upsertCVEs(ctx, nvdResp.Vulnerabilities, isBackfill)

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

func (w *Worker) upsertCVEs(ctx context.Context, entries []NVDCVEEntry, isBackfill bool) {
	for _, entry := range entries {
		cve := entry.CVE

		description := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				description = d.Value
				break
			}
		}

		var score float64
		var vector string
		if len(cve.Metrics.CvssMetricV31) > 0 {
			score = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			vector = cve.Metrics.CvssMetricV31[0].CvssData.VectorString
		} else if len(cve.Metrics.CvssMetricV30) > 0 {
			score = cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
			vector = cve.Metrics.CvssMetricV30[0].CvssData.VectorString
		} else if len(cve.Metrics.CvssMetricV2) > 0 {
			score = cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
			vector = cve.Metrics.CvssMetricV2[0].CvssData.VectorString
		}

		cweID := ""
		for _, weak := range cve.Weaknesses {
			for _, d := range weak.Description {
				if strings.HasPrefix(d.Value, "CWE-") {
					cweID = d.Value
					break
				}
			}
			if cweID != "" {
				break
			}
		}

		var references []string
		exploitAvailable := false
		for _, ref := range cve.References {
			u, err := url.Parse(ref.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}

			// Check for exploit tags
			for _, tag := range ref.Tags {
				if strings.ToLower(tag) == "exploit" {
					exploitAvailable = true
					break
				}
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
			log.Printf("Worker: Invalid published date %q for %s: %v — skipping", cve.Published, cve.ID, err)
			continue
		}
		modDate, err := parseNVDDate(cve.LastModified)
		if err != nil {
			log.Printf("Worker: Invalid lastModified date %q for %s: %v — skipping", cve.LastModified, cve.ID, err)
			continue
		}

		model := models.CVE{
			CVEID:          cve.ID,
			Description:    description,
			CVSSScore:      score,
			VectorString:   vector,
			CWEID:          cweID,
			References:     references,
			PublishedDate:  pubDate,
			UpdatedDate:    modDate,
			Configurations: cve.Configurations,
			ExploitAvailable: exploitAvailable,
		}

		vendor, product := model.GetDetectedProduct()
		if vendor == "" && (config.AppConfig.GeminiAPIKey != "" || config.AppConfig.LLMProvider == "ollama") {
			llmModel := config.AppConfig.GeminiModel
			if config.AppConfig.LLMProvider == "ollama" {
				llmModel = config.AppConfig.LLMModel
			}

			// Call LLM as fallback
			products, err := llm.ExtractVendorProduct(ctx, config.AppConfig.LLMProvider, config.AppConfig.GeminiAPIKey, config.AppConfig.LLMEndpoint, llmModel, model.Description)
			if err == nil && len(products) > 0 {
				// Use the first one as primary
				vendor, product = products[0].Vendor, products[0].Product
				log.Printf("Worker: LLM refined detection for %s: found %d products. Primary: %s / %s", model.CVEID, len(products), vendor, product)

				// Add all to affected_products if not already there
				existing := model.GetAffectedProducts()
				for _, p := range products {
					found := false
					for _, ep := range existing {
						if ep.Vendor == p.Vendor && ep.Product == p.Product {
							found = true
							break
						}
					}
					if !found {
						existing = append(existing, models.AffectedProduct{
							Vendor:      p.Vendor,
							Product:     p.Product,
							Version:     p.Version,
							Type:        "a",
							Unconfirmed: true,
						})
					}
				}
				model.AffectedProducts = existing
			} else if err != nil {
				log.Printf("Worker: LLM extraction failed for %s: %v", model.CVEID, err)
			}
		}
		model.Vendor = vendor
		model.Product = product
		model.AffectedProducts = model.GetAffectedProducts()

		query := `
			INSERT INTO cves (cve_id, description, cvss_score, vector_string, cwe_id, "references", configurations, published_date, updated_date, vendor, product, affected_products, exploit_available)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (cve_id) DO UPDATE SET
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
		err = w.Pool.QueryRow(ctx, query, model.CVEID, model.Description, model.CVSSScore, model.VectorString, model.CWEID, model.References, model.Configurations, model.PublishedDate, model.UpdatedDate, model.Vendor, model.Product, model.AffectedProducts, model.ExploitAvailable).Scan(&model.ID)
		if err != nil {
			log.Printf("Worker: Error upserting CVE %s: %v", cve.ID, err)
			continue
		}

		// Trigger on-demand enrichment for new/updated CVE
		select {
		case w.enrichmentQueue <- model.ID:
		default:
			// Queue full, will be picked up by background cron
		}

		// Check for alerts after successful upsert (only if not backfilling)
		if !isBackfill {
			if err := w.enqueueAlertsForCVE(ctx, model); err != nil {
				log.Printf("Worker: [ERROR] %v", err)
			}
		}
	}
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
		log.Printf("Worker: Error updating sync stats: %v", err)
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
		log.Printf("Worker: Error updating backfill progress: %v", err)
	}
}

func (w *Worker) clearBackfillProgress(ctx context.Context) {
	_, _ = w.Pool.Exec(ctx, "DELETE FROM sync_state WHERE key = 'nvd_backfill_index'")
}
