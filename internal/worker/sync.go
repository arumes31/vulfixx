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
var defaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type NVDResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
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
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type CISAKEVResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
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

func fetchCISAKEVPeriodically(ctx context.Context) {
	fetchFromCISAKEV(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fetchFromCISAKEV(ctx)
		}
	}
}

func fetchFromCISAKEV(ctx context.Context) {
	log.Println("Worker: [SYNC] Fetching CISA KEV catalog...")
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", defaultCISAKEVURL, nil)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to create CISA KEV request: %v", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CISA KEV: %v", err)
		return
	}
	defer resp.Body.Close()

	var kevResp CISAKEVResponse
	if err := json.NewDecoder(resp.Body).Decode(&kevResp); err != nil {
		log.Printf("Worker: [ERROR] Failed to decode CISA KEV: %v", err)
		return
	}

	total := len(kevResp.Vulnerabilities)
	log.Printf("Worker: [SYNC] Updating %d CISA KEV records...", total)

	if _, err := db.Pool.Exec(ctx, "UPDATE cves SET cisa_kev = false"); err != nil {
		log.Printf("Worker: [ERROR] Failed to reset CISA KEV status: %v", err)
		return
	}

	batchSize := 100
	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}
		ids := make([]string, 0, batchSize)
		for _, v := range kevResp.Vulnerabilities[i:end] {
			ids = append(ids, v.CVEID)
		}
		_, err := db.Pool.Exec(ctx, "UPDATE cves SET cisa_kev = true WHERE cve_id = ANY($1)", ids)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to update KEV batch: %v", err)
		}
	}
	log.Println("Worker: [SYNC] CISA KEV update complete.")
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
		log.Printf("Worker: Failed to update sync_state: %v", err)
	}
}

func nvdAPIDelay() time.Duration {
	if os.Getenv("NVD_API_KEY") != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
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

		req, err := http.NewRequestWithContext(ctx, "GET", nvdURL, nil)
		if err != nil {
			log.Println("Error creating NVD request:", err)
			return
		}
		if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		var resp *http.Response
		maxRetries := 3
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
			log.Printf("Worker: [ERROR] NVD API call failed: %v, retrying (%d/%d)...", retryErr, retry+1, maxRetries)
			time.Sleep(delay * time.Duration(retry+1))
		}

		if retryErr != nil {
			log.Println("Error fetching from NVD after retries:", retryErr)
			return
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			log.Printf("Worker: NVD rate-limited (HTTP %d), backing off...", resp.StatusCode)
			time.Sleep(30 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			log.Printf("NVD API returned non-retriable status: %d", resp.StatusCode)
			return
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			_ = resp.Body.Close()
			log.Println("Error decoding NVD response:", err)
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

func upsertCVEs(ctx context.Context, vulnerabilities []struct {
	CVE struct {
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
	} `json:"cve"`
}, sendAlerts bool) (inserted int, updated int) {
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
		pubDate, _ := time.Parse(time.RFC3339, cveData.Published)
		modDate, _ := time.Parse(time.RFC3339, cveData.LastModified)
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
			log.Printf("Worker: [ERROR] Failed to upsert CVE %s: %v", cve.CVEID, err)
			_ = db.Pool.QueryRow(ctx, "SELECT id FROM cves WHERE cve_id = $1", cve.CVEID).Scan(&id)
		}
		if id > 0 && sendAlerts {
			cve.ID = id
			alertJob, _ := json.Marshal(cve)
			db.RedisClient.LPush(ctx, "cve_alerts_queue", alertJob)
		}
	}
	return inserted, updated
}

func syncEPSSPeriodically(ctx context.Context) {
	syncEPSS(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncEPSS(ctx)
		}
	}
}

func syncEPSS(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting EPSS score synchronization...")
	rows, err := db.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE created_at > NOW() - INTERVAL '30 days'")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for EPSS sync: %v", err)
		return
	}
	defer rows.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			continue
		}
		epssURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID)
		req, _ := http.NewRequestWithContext(ctx, "GET", epssURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to fetch EPSS for %s: %v", cveID, err)
			continue
		}
		var epssResp struct {
			Data []struct {
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if len(epssResp.Data) > 0 {
			score := 0.0
			if _, err := fmt.Sscanf(epssResp.Data[0].EPSS, "%f", &score); err != nil {
				log.Printf("EPSS: Failed to parse score for %s: %v", cveID, err)
				continue
			}
			_, err = db.Pool.Exec(ctx, "UPDATE cves SET epss_score = $1 WHERE cve_id = $2", score, cveID)
			if err != nil {
				log.Printf("Worker: [ERROR] Failed to update EPSS for %s: %v", cveID, err)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Println("Worker: [SYNC] EPSS score synchronization complete.")
}

func syncGitHubBuzzPeriodically(ctx context.Context) {
	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncGitHubBuzz(ctx)
		}
	}
}

func syncGitHubBuzz(ctx context.Context) {
	log.Println("Worker: [SYNC] Starting GitHub Social Buzz synchronization...")
	rows, err := db.Pool.Query(ctx, "SELECT cve_id FROM cves WHERE created_at > NOW() - INTERVAL '14 days' ORDER BY created_at DESC")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch CVEs for GitHub sync: %v", err)
		return
	}
	defer rows.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			continue
		}
		githubURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", cveID)
		req, _ := http.NewRequestWithContext(ctx, "GET", githubURL, nil)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "Vulfixx-Threat-Intel")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to fetch GitHub buzz for %s: %v", cveID, err)
			continue
		}
		if resp.StatusCode == 403 {
			resp.Body.Close()
			log.Printf("Worker: [WARN] GitHub API rate limited, skipping remaining CVEs")
			break
		}
		var ghResp struct {
			TotalCount int `json:"total_count"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		_, err = db.Pool.Exec(ctx, "UPDATE cves SET github_poc_count = $1 WHERE cve_id = $2", ghResp.TotalCount, cveID)
		if err != nil {
			log.Printf("Worker: [ERROR] Failed to update GitHub buzz for %s: %v", cveID, err)
		}
		time.Sleep(7 * time.Second)
	}
	log.Println("Worker: [SYNC] GitHub Social Buzz synchronization complete.")
}
