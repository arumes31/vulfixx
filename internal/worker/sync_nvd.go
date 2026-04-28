package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"math"
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

func (w *Worker) fetchCVEsPeriodically(ctx context.Context) {
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
	lastSync := w.getLastSyncTime(ctx)
	if lastSync.IsZero() {
		log.Println("Worker: No prior sync found — starting full NVD backfill...")
		w.runFullSync(ctx, true)
	} else {
		log.Printf("Worker: Incremental sync — fetching CVEs modified since %s", lastSync.Format(time.RFC3339))
		w.runFullSync(ctx, false)
	}
}

func (w *Worker) runFullSync(ctx context.Context, isBackfill bool) {
	baseURL := defaultNVDBaseURL
	if envURL := os.Getenv("NVD_API_URL"); envURL != "" {
		parsed, err := url.Parse(envURL)
		if err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
			baseURL = parsed.String()
		}
	}

	params := url.Values{}
	if !isBackfill {
		lastSync := w.getLastSyncTime(ctx)
		params.Set("lastModStartDate", lastSync.Format(time.RFC3339))
		params.Set("lastModEndDate", time.Now().Format(time.RFC3339))
	}

	resultsPerPage := 2000
	startIndex := 0

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
		retryCount = 0 // reset on success

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			log.Println("Worker: Rate limited by NVD, waiting 30s...")
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

		if resp.StatusCode != http.StatusOK {
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

		w.upsertCVEs(ctx, nvdResp.Vulnerabilities)

		startIndex += resultsPerPage
		if startIndex >= nvdResp.TotalResults {
			break
		}

		// NVD recommends 0.6s delay with API Key, 6s without.
		nvdAPIDelay := 6 * time.Second
		if os.Getenv("NVD_API_KEY") != "" {
			nvdAPIDelay = 600 * time.Millisecond
		}
		time.Sleep(nvdAPIDelay)
	}

	w.updateLastSyncTime(ctx)
}

func (w *Worker) upsertCVEs(ctx context.Context, entries []NVDCVEEntry) {
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
		for _, ref := range cve.References {
			references = append(references, ref.URL)
		}

		pubDate, err := time.Parse(time.RFC3339Nano, cve.Published)
		if err != nil {
			pubDate, err = time.Parse(time.RFC3339, cve.Published)
			if err != nil {
				log.Printf("Worker: Invalid published date %q for %s: %v — skipping", cve.Published, cve.ID, err)
				continue
			}
		}
		modDate, err := time.Parse(time.RFC3339Nano, cve.LastModified)
		if err != nil {
			modDate, err = time.Parse(time.RFC3339, cve.LastModified)
			if err != nil {
				log.Printf("Worker: Invalid lastModified date %q for %s: %v — skipping", cve.LastModified, cve.ID, err)
				continue
			}
		}

		model := models.CVE{
			CVEID:         cve.ID,
			Description:   description,
			CVSSScore:     score,
			VectorString:  vector,
			CWEID:         cweID,
			References:    references,
			PublishedDate: pubDate,
			UpdatedDate:   modDate,
		}

		query := `
			INSERT INTO cves (cve_id, description, cvss_score, vector_string, cwe_id, "references", published_date, updated_date)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (cve_id) DO UPDATE SET
				description = EXCLUDED.description,
				cvss_score = EXCLUDED.cvss_score,
				vector_string = EXCLUDED.vector_string,
				cwe_id = EXCLUDED.cwe_id,
				"references" = EXCLUDED."references",
				updated_date = EXCLUDED.updated_date,
				updated_at = CURRENT_TIMESTAMP
		`
		_, err = w.Pool.Exec(ctx, query, model.CVEID, model.Description, model.CVSSScore, model.VectorString, model.CWEID, model.References, model.PublishedDate, model.UpdatedDate)
		if err != nil {
			log.Printf("Worker: Error upserting CVE %s: %v", cve.ID, err)
			continue
		}

		// Check for alerts after successful upsert
		w.enqueueAlertsForCVE(ctx, model)
	}
}

func (w *Worker) getLastSyncTime(ctx context.Context) time.Time {
	var lastSync time.Time
	err := w.Pool.QueryRow(ctx, "SELECT last_run FROM worker_sync_stats WHERE task_name = 'nvd_sync'").Scan(&lastSync)
	if err != nil {
		return time.Time{}
	}
	return lastSync
}

func (w *Worker) updateLastSyncTime(ctx context.Context) {
	_, err := w.Pool.Exec(ctx, `
		INSERT INTO worker_sync_stats (task_name, last_run)
		VALUES ('nvd_sync', CURRENT_TIMESTAMP)
		ON CONFLICT (task_name) DO UPDATE SET last_run = CURRENT_TIMESTAMP
	`)
	if err != nil {
		log.Printf("Worker: Error updating sync stats: %v", err)
	}
}
