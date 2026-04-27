package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
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
		URL string `json:"url"`
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
}

type NVDCVEEntry struct {
	CVE NVDCVE `json:"cve"`
}

type NVDResponse struct {
	TotalResults    int           `json:"totalResults"`
	Vulnerabilities []NVDCVEEntry `json:"vulnerabilities"`
}

func fetchCVEsPeriodically(ctx context.Context) {
	fetchFromNVD(ctx)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fetchFromNVD(ctx)
		}
	}
}

func fetchFromNVD(ctx context.Context) {
	lastSync := getLastSyncTime(ctx)
	if lastSync.IsZero() {
		log.Println("Worker: No prior sync found — starting full NVD backfill...")
		runFullSync(ctx, true)
	} else {
		log.Printf("Worker: Incremental sync — fetching CVEs modified since %s", lastSync.Format(time.RFC3339))
		runFullSync(ctx, false)
	}
}

func runFullSync(ctx context.Context, isBackfill bool) {
	baseURL := defaultNVDBaseURL
	if envURL := os.Getenv("NVD_API_URL"); envURL != "" {
		parsed, err := url.Parse(envURL)
		if err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
			baseURL = parsed.String()
		}
	}

	lastSync := getLastSyncTime(ctx)
	client := &http.Client{Timeout: 60 * time.Second}
	const pageSize = 2000
	startIndex := 0
	totalResults := -1
	syncStart := time.Now().UTC()
	delay := nvdAPIDelay()

	rateLimitRetries := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		nvdURL := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", baseURL, pageSize, startIndex)
		if !isBackfill && !lastSync.IsZero() {
			startDate := lastSync.Add(-1 * time.Minute).Format("2006-01-02T15:04:05.000")
			nvdURL += fmt.Sprintf("&lastModStartDate=%s", url.QueryEscape(startDate))
			nvdURL += fmt.Sprintf("&lastModEndDate=%s", url.QueryEscape(syncStart.Format("2006-01-02T15:04:05.000")))
		}

		// #nosec G704 -- baseURL is either constant or from admin-controlled environment variable
		req, err := http.NewRequestWithContext(ctx, "GET", nvdURL, nil)
		if err != nil {
			log.Println("Error creating NVD request:", sanitizeForLog(err.Error()))
			return
		}
		if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		var resp *http.Response
		maxRetries := 3
		maxRateLimitRetries := 5
		var retryErr error
		for retry := 0; retry < maxRetries; retry++ {
			resp, retryErr = client.Do(req)
			if retryErr == nil {
				if resp.StatusCode == http.StatusOK {
					break
				}
				if resp.StatusCode >= 500 && resp.StatusCode < 600 {
					_ = resp.Body.Close()
					log.Printf("Worker: NVD API returned status %d, retrying (%d/%d)...", resp.StatusCode, retry+1, maxRetries)
					time.Sleep(delay * time.Duration(retry+1))
					continue
				}
				break
			}
			log.Printf("Worker: [ERROR] NVD API call failed: %v, retrying (%d/%d)...", sanitizeForLog(retryErr.Error()), retry+1, maxRetries)
			time.Sleep(delay * time.Duration(retry+1))
		}

		if retryErr != nil {
			log.Println("Error fetching from NVD after retries:", sanitizeForLog(retryErr.Error()))
			return
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			rateLimitRetries++
			if rateLimitRetries >= maxRateLimitRetries {
				log.Printf("Worker: [ERROR] Max NVD rate-limit retries reached (%d)", maxRateLimitRetries)
				return
			}
			log.Printf("Worker: NVD rate-limited (HTTP %d), backing off (%d/%d)...", resp.StatusCode, rateLimitRetries, maxRateLimitRetries)
			time.Sleep(30 * time.Second)
			continue
		}
		rateLimitRetries = 0

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			log.Printf("NVD API returned non-retriable status: %d", resp.StatusCode)
			return
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			_ = resp.Body.Close()
			log.Println("Error decoding NVD response:", sanitizeForLog(err.Error()))
			return
		}
		_ = resp.Body.Close()

		if totalResults < 0 {
			totalResults = nvdResp.TotalResults
			if isBackfill {
				log.Printf("Worker: [SYNC] Starting full backfill of %d CVEs", totalResults)
			} else {
				log.Printf("Worker: [SYNC] Incremental sync found %d modified CVEs", totalResults)
			}
		}

		inserted, updated := upsertCVEs(ctx, nvdResp.Vulnerabilities, !isBackfill)
		startIndex += len(nvdResp.Vulnerabilities)
		progress := 0.0
		if totalResults > 0 {
			progress = float64(startIndex) / float64(totalResults) * 100
		}
		log.Printf("Worker: [PROGRESS] %.1f%% (%d/%d) | New: %d, Updated: %d", progress, startIndex, totalResults, inserted, updated)

		if startIndex >= totalResults || len(nvdResp.Vulnerabilities) == 0 {
			break
		}
		time.Sleep(delay)
	}

	setLastSyncTime(ctx, syncStart)
	log.Println("Worker: NVD sync complete.")
}

func upsertCVEs(ctx context.Context, vulnerabilities []NVDCVEEntry, sendAlerts bool) (inserted int, updated int) {
	for _, v := range vulnerabilities {
		cveData := v.CVE
		desc := ""
		for _, d := range cveData.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		score := 0.0
		vector := ""
		if len(cveData.Metrics.CvssMetricV31) > 0 {
			score = cveData.Metrics.CvssMetricV31[0].CvssData.BaseScore
			vector = cveData.Metrics.CvssMetricV31[0].CvssData.VectorString
		} else if len(cveData.Metrics.CvssMetricV30) > 0 {
			score = cveData.Metrics.CvssMetricV30[0].CvssData.BaseScore
			vector = cveData.Metrics.CvssMetricV30[0].CvssData.VectorString
		} else if len(cveData.Metrics.CvssMetricV2) > 0 {
			score = cveData.Metrics.CvssMetricV2[0].CvssData.BaseScore
			vector = cveData.Metrics.CvssMetricV2[0].CvssData.VectorString
		}
		var refs []string
		for _, r := range cveData.References {
			refs = append(refs, r.URL)
		}
		pubDate, err1 := time.Parse(time.RFC3339, cveData.Published)
		if err1 != nil {
			log.Printf("Worker: [WARN] Failed to parse published date for %s (%q): %v", sanitizeForLog(cveData.ID), sanitizeForLog(cveData.Published), sanitizeForLog(err1.Error()))
			continue
		}
		modDate, err2 := time.Parse(time.RFC3339, cveData.LastModified)
		if err2 != nil {
			log.Printf("Worker: [WARN] Failed to parse modified date for %s (%q): %v", sanitizeForLog(cveData.ID), sanitizeForLog(cveData.LastModified), sanitizeForLog(err2.Error()))
			continue
		}
		cwe := ""
		for _, w := range cveData.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
					cwe = d.Value
					break
				}
			}
			if cwe != "" {
				break
			}
		}
		cve := models.CVE{
			CVEID:         cveData.ID,
			Description:   desc,
			CVSSScore:     score,
			VectorString:  vector,
			CWEID:         cwe,
			References:    refs,
			PublishedDate: pubDate,
			UpdatedDate:   modDate,
		}
		var id int
		var tag string
		err := db.Pool.QueryRow(ctx, `
			WITH upsert AS (
				INSERT INTO cves (cve_id, description, cvss_score, vector_string, cwe_id, "references", published_date, updated_date)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (cve_id) DO UPDATE SET
					description = EXCLUDED.description,
					cvss_score = EXCLUDED.cvss_score,
					vector_string = EXCLUDED.vector_string,
					cwe_id = EXCLUDED.cwe_id,
					"references" = EXCLUDED."references",
					updated_date = EXCLUDED.updated_date
				RETURNING id, (xmax = 0) AS is_insert
			)
			SELECT id, CASE WHEN is_insert THEN 'ins' ELSE 'upd' END FROM upsert
		`, cve.CVEID, cve.Description, cve.CVSSScore, cve.VectorString, cve.CWEID, refs, cve.PublishedDate, cve.UpdatedDate).Scan(&id, &tag)
		if err == nil {
			if tag == "ins" {
				inserted++
			} else {
				updated++
			}
		} else {
			log.Printf("Worker: [ERROR] Failed to upsert CVE %s: %v", sanitizeForLog(cve.CVEID), sanitizeForLog(err.Error()))
			_ = db.Pool.QueryRow(ctx, "SELECT id FROM cves WHERE cve_id = $1", cve.CVEID).Scan(&id)
		}
		if id > 0 && sendAlerts {
			cve.ID = id
			alertJob, err := json.Marshal(cve)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to marshal alert for %s: %v", sanitizeForLog(cve.CVEID), sanitizeForLog(err.Error()))
				continue
			}
			if err := db.RedisClient.LPush(ctx, "cve_alerts_queue", alertJob).Err(); err != nil {
				log.Printf("Worker: [ERROR] Failed to enqueue alert for %d (%s): %v", id, sanitizeForLog(cve.CVEID), sanitizeForLog(err.Error()))
			}
		}
	}
	return inserted, updated
}

func getLastSyncTime(ctx context.Context) time.Time {
	var val string
	err := db.Pool.QueryRow(ctx, "SELECT value FROM sync_state WHERE key = 'last_nvd_sync'").Scan(&val)
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}
	}
	return t
}

func setLastSyncTime(ctx context.Context, t time.Time) {
	val := t.UTC().Format(time.RFC3339)
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO sync_state (key, value, updated_at)
		VALUES ('last_nvd_sync', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	if err != nil {
		log.Printf("Worker: Failed to update sync_state: %v", sanitizeForLog(err.Error()))
	}
}

func sanitizeForLog(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, string(rune(0)), "")
	return s
}

func nvdAPIDelay() time.Duration {
	if os.Getenv("NVD_API_KEY") != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}
