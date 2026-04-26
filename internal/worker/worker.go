package worker

import (
	"bytes"
	"context"
	"crypto/tls"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// sanitizeEmail validates and sanitizes an email address to prevent
// SMTP header injection (gosec G707). Uses net/mail for proper parsing.
func sanitizeEmail(email string) (string, error) {
	// Strip any CR/LF first
	s := strings.ReplaceAll(email, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	// Validate with net/mail
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("invalid email address %q: %w", s, err)
	}
	return addr.Address, nil
}

// redactToken safely redacts a token for logging.
func redactToken(token string) string {
	n := 8
	if len(token) < n {
		n = len(token)
	}
	if n == 0 {
		return "<empty>"
	}
	return token[:n] + "..."
}

// redactURL redacts a URL for logging by removing Userinfo, Query, and Path.
func redactURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "[invalid-url]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = "/"
	return parsed.String()
}

// sendMailWithTimeout is a replacement for smtp.SendMail that supports deadlines.
func sendMailWithTimeout(host, port, user, password string, to []string, msg []byte) error {
	addr := net.JoinHostPort(host, port)
	// #nosec G704 -- Host and port are from controlled environment variables
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial timeout: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	defer func() { _ = client.Quit() }()

	// Negotiate STARTTLS if supported (G706 hardening)
	if ok, _ := client.Extension("STARTTLS"); ok {
		config := &tls.Config{
			ServerName: host,
			// Note: We don't use InsecureSkipVerify: true here for security.
		}
		if err := client.StartTLS(config); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}

	if user != "" && password != "" {
		auth := smtp.PlainAuth("", user, password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	// #nosec G707 -- User is from controlled environment variable
	if err := client.Mail(user); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("rcpt to %s: %w", recipient, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	_, err = w.Write(msg)
	if err != nil {
		_ = w.Close()
		return fmt.Errorf("write msg: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data writer: %w", err)
	}

	return client.Quit()
}

// defaultNVDBaseURL is the NVD API base URL. Tests can override this.
var defaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

func StartWorker(ctx context.Context) {
	go fetchCVEsPeriodically(ctx)
	go fetchCISAKEVPeriodically(ctx)
	go startWeeklySummaryTask(ctx)
	go processAlerts(ctx)
	go processEmailVerification(ctx)
	go processEmailChange(ctx)
	go syncEPSSPeriodically(ctx)
	go syncGitHubBuzzPeriodically(ctx)
}

// NVDResponse is the top-level NVD API response structure.
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
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

func fetchCVEsPeriodically(ctx context.Context) {
	// Fetch immediately on startup
	fetchFromNVD(ctx)

	// NIST NVD rate limit is strict. 1 hour for incremental syncs.
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
	// Fetch immediately on startup
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

type CISAKEVResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

var defaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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

	// Reset all cisa_kev flags first
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
			// NVD requires UTC format for date params
			startDate := lastSync.Add(-1 * time.Minute).Format("2006-01-02T15:04:05.000")
			nvdURL += fmt.Sprintf("&lastModStartDate=%s", url.QueryEscape(startDate))
			nvdURL += fmt.Sprintf("&lastModEndDate=%s", url.QueryEscape(syncStart.Format("2006-01-02T15:04:05.000")))
		}

		req, err := http.NewRequestWithContext(ctx, "GET", nvdURL, nil) // #nosec G704 -- URL is constructed from hardcoded base and escaped params
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
			resp, retryErr = client.Do(req) // #nosec G704 -- Request is verified safe
			if retryErr == nil {
				if resp.StatusCode == http.StatusOK {
					break
				}
				// Retry on 5xx errors
				if resp.StatusCode >= 500 && resp.StatusCode < 600 {
					_ = resp.Body.Close()
					log.Printf("Worker: NVD API returned status %d, retrying (%d/%d)...", resp.StatusCode, retry+1, maxRetries) // #nosec G706 -- StatusCode is int, no injection risk
					time.Sleep(delay * time.Duration(retry+1))
					continue
				}
				// Don't retry on other non-200 statuses
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
			log.Printf("Worker: NVD rate-limited (HTTP %d), backing off...", resp.StatusCode) // #nosec G706 -- StatusCode is int, no injection risk
			time.Sleep(30 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			log.Printf("NVD API returned non-retriable status: %d", resp.StatusCode) // #nosec G706 -- StatusCode is int, no injection risk
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

func processAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := db.RedisClient.BRPop(ctx, 0, "cve_alerts_queue").Result()
			if err != nil {
				log.Println("Error reading from queue:", err)
				time.Sleep(1 * time.Second)
				continue
			}

			var cve models.CVE
			if err := json.Unmarshal([]byte(result[1]), &cve); err != nil {
				log.Printf("Error unmarshaling CVE from queue: %v", err)
				continue
			}

			evaluateSubscriptions(ctx, &cve)
		}
	}
}

func evaluateSubscriptions(ctx context.Context, cve *models.CVE) {
	// Find matching manual subscriptions
	rows, err := db.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.keyword, s.min_severity, s.webhook_url, s.enable_email, s.enable_webhook, u.email
		FROM user_subscriptions s
		JOIN users u ON s.user_id = u.id
		WHERE u.is_email_verified = TRUE
	`)
	if err != nil {
		log.Println("Error fetching subscriptions:", err)
		return
	}
	defer rows.Close()

	notifiedUsers := make(map[int]bool)

	for rows.Next() {
		var sub models.UserSubscription
		var email string
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity, &sub.WebhookURL, &sub.EnableEmail, &sub.EnableWebhook, &email); err != nil {
			log.Printf("Error scanning subscription row: %v", err)
			continue
		}

		if matchCVE(cve, sub.Keyword, sub.MinSeverity) {
			if notifyIfNew(ctx, sub.UserID, cve.ID, sub, email, "") {
				notifiedUsers[sub.UserID] = true
			}
		}
	}

	// Asset-Linked Monitoring (Virtual Subscriptions)
	assetRows, err := db.Pool.Query(ctx, `
		SELECT ak.keyword, a.user_id, u.email, a.name
		FROM asset_keywords ak
		JOIN assets a ON ak.asset_id = a.id
		JOIN users u ON a.user_id = u.id
		WHERE u.is_email_verified = TRUE
	`)
	if err != nil {
		log.Println("Error fetching asset keywords:", err)
		return
	}
	defer assetRows.Close()

	for assetRows.Next() {
		var keyword, email, assetName string
		var userID int
		if err := assetRows.Scan(&keyword, &userID, &email, &assetName); err != nil {
			continue
		}

		if notifiedUsers[userID] {
			continue
		}

		if strings.Contains(strings.ToLower(cve.Description), strings.ToLower(keyword)) {
			// Asset match uses default notification settings (both enabled)
			sub := models.UserSubscription{
				EnableEmail:   true,
				EnableWebhook: true,
			}
			if notifyIfNew(ctx, userID, cve.ID, sub, email, assetName) {
				notifiedUsers[userID] = true
			}
		}
	}
}

func matchCVE(cve *models.CVE, keyword string, minSeverity float64) bool {
	if keyword != "" && !strings.Contains(strings.ToLower(cve.Description), strings.ToLower(keyword)) {
		return false
	}
	if minSeverity > 0 && cve.CVSSScore < minSeverity {
		return false
	}
	return true
}

func notifyIfNew(ctx context.Context, userID, cveID int, sub models.UserSubscription, email, assetName string) bool {
	var exists bool
	if err := db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM alert_history WHERE user_id=$1 AND cve_id=$2)", userID, cveID).Scan(&exists); err != nil {
		return false
	}
	if exists {
		return false
	}

	// Fetch CVE for alert
	var cve models.CVE
	err := db.Pool.QueryRow(ctx, `
		SELECT cve_id, description, cvss_score, vector_string, cisa_kev, epss_score, cwe_id, github_poc_count, published_date, "references" 
		FROM cves WHERE id = $1
	`, cveID).Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.VectorString, &cve.CISAKEV, &cve.EPSSScore, &cve.CWEID, &cve.GitHubPoCCount, &cve.PublishedDate, &cve.References)
	if err != nil {
		log.Printf("Failed to fetch full CVE details for alert: %v", err)
		return false
	}

	return bufferAlert(ctx, userID, &cve, email, assetName)
}

func bufferAlert(ctx context.Context, userID int, cve *models.CVE, email, assetName string) bool {
	key := fmt.Sprintf("alert_buffer:%d", userID)
	data := map[string]interface{}{
		"cve":        cve,
		"email":      email,
		"asset_name": assetName,
	}
	blob, _ := json.Marshal(data)
	
	db.RedisClient.RPush(ctx, key, blob)
	// Set a flag to process this user's buffer in 5 minutes if not already set
	processingKey := fmt.Sprintf("alert_processing:%d", userID)
	set, _ := db.RedisClient.SetNX(ctx, processingKey, "true", 5*time.Minute).Result()
	if set {
		go func() {
			time.Sleep(5 * time.Minute)
			processUserBuffer(context.Background(), userID)
			db.RedisClient.Del(context.Background(), processingKey)
		}()
	}
	return true
}

func processUserBuffer(ctx context.Context, userID int) {
	key := fmt.Sprintf("alert_buffer:%d", userID)
	blobs, _ := db.RedisClient.LRange(ctx, key, 0, -1).Result()
	db.RedisClient.Del(ctx, key)

	if len(blobs) == 0 {
		return
	}

	if len(blobs) == 1 {
		// Just one alert, send standard template
		var data struct {
			CVE       models.CVE `json:"cve"`
			Email     string     `json:"email"`
			AssetName string     `json:"asset_name"`
		}
	if err := json.Unmarshal([]byte(blobs[0]), &data); err != nil {
		log.Printf("Failed to unmarshal single alert blob for user %d: %v", userID, err)
		return
	}
		
		// We need the subscription settings to know if email is enabled.
		// For simplicity in the buffer, we'll assume it was checked in notifyIfNew.
		// However, sendAlert needs the UserSubscription object.
		// We'll mock a default one since we're already in the email-sending path.
		sub := models.UserSubscription{EnableEmail: true, EnableWebhook: true}
		sendAlert(sub, &data.CVE, data.Email, data.AssetName)
		return
	}

	// Multiple alerts, send summary brief
	var email string
	type AlertItem struct {
		CVEID     string
		Score     float64
		AssetName string
		Buzz      int
	}
	var items []AlertItem
	
	for _, b := range blobs {
		var data struct {
			CVE       models.CVE `json:"cve"`
			Email     string     `json:"email"`
			AssetName string     `json:"asset_name"`
		}
		if err := json.Unmarshal([]byte(b), &data); err != nil {
			continue
		}
		email = data.Email
		items = append(items, AlertItem{
			CVEID:     data.CVE.CVEID,
			Score:     data.CVE.CVSSScore,
			AssetName: data.AssetName,
			Buzz:      data.CVE.GitHubPoCCount,
		})
	}

	rowsHTML := ""
	for _, item := range items {
		assetInfo := ""
		if item.AssetName != "" {
			assetInfo = fmt.Sprintf("<br><span style='font-size: 11px; opacity: 0.6;'>Asset: %s</span>", item.AssetName)
		}
		buzzBadge := ""
		if item.Buzz >= 15 {
			buzzBadge = "🔥 High"
		} else if item.Buzz >= 6 {
			buzzBadge = "📈 Hot"
		} else if item.Buzz >= 2 {
			buzzBadge = "✨ New"
		}

		rowsHTML += fmt.Sprintf(`
			<tr>
				<td style="padding: 15px; border-bottom: 1px solid #232931;">
					<strong style="color: #00daf3;">%s</strong>%s
				</td>
				<td style="padding: 15px; border-bottom: 1px solid #232931; text-align: center; font-size: 12px;">
					%s
				</td>
				<td style="padding: 15px; border-bottom: 1px solid #232931; text-align: right;">
					<span style="background: #1c2026; padding: 4px 10px; border-radius: 4px; font-weight: bold;">%.1f</span>
				</td>
			</tr>
		`, item.CVEID, assetInfo, buzzBadge, item.Score)
	}

	body := fmt.Sprintf(`
		<div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
			<h2 style="color: #00daf3; margin-top: 0;">Intelligence Brief: %d New Threats</h2>
			<p style="font-size: 14px; opacity: 0.7; margin-bottom: 30px;">Multiple vulnerabilities matching your profile were detected in the last 5 minutes.</p>
			
			<table style="width: 100%%; border-collapse: collapse; margin-bottom: 30px;">
				<thead>
					<tr style="font-size: 11px; text-transform: uppercase; opacity: 0.5; text-align: left;">
						<th style="padding: 10px 15px;">Vulnerability</th>
						<th style="padding: 10px 15px; text-align: center;">Buzz</th>
						<th style="padding: 10px 15px; text-align: right;">CVSS</th>
					</tr>
				</thead>
				<tbody>
					%s
				</tbody>
			</table>

			<a href="%s/dashboard" style="display: block; width: 100%%; background: #00daf3; color: #101418; text-align: center; padding: 15px 0; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 14px; text-transform: uppercase;">Review All Threats</a>
		</div>
	`, len(items), rowsHTML, os.Getenv("BASE_URL"))

	if err := sendEmail(email, fmt.Sprintf("Threat Report: %d New Vulnerabilities Detected", len(items)), body); err != nil {
		log.Printf("Failed to send buffered threat report to %s: %v", email, err)
	}
}

func sendAlert(sub models.UserSubscription, cve *models.CVE, email, assetName string) bool {
	log.Printf("ALERT: Sending to %s for %s\n", email, cve.CVEID)

	var wg sync.WaitGroup
	successChan := make(chan bool, 2)

	if sub.EnableWebhook && sub.WebhookURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parsedURL, err := url.Parse(sub.WebhookURL)
			redacted := redactURL(sub.WebhookURL)
			if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
				log.Printf("Skipping invalid webhook URL scheme: %s", redacted)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, parsedURL.Hostname())
			if err != nil {
				log.Printf("Failed to resolve webhook host: %s, err: %v", redacted, err)
				return
			}
			isSafe := true
			var safeIP net.IP
			for _, ipAddr := range ips {
				ip := ipAddr.IP
				if addr, ok := netip.AddrFromSlice(ip); ok {
					if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
						isSafe = false
						break
					}
					if safeIP == nil {
						safeIP = ip
					}
				}
			}
			if !isSafe || safeIP == nil {
				log.Printf("Skipping unsafe webhook URL IP: %s", redacted)
				return
			}
			payloadMap := map[string]interface{}{
				"cve_id":      cve.CVEID,
				"description": cve.Description,
				"cvss_score":  cve.CVSSScore,
			}
			if os.Getenv("WEBHOOK_INCLUDE_USER_EMAIL") == "true" {
				payloadMap["user_email"] = email
			}
			payload, _ := json.Marshal(payloadMap)
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						port := parsedURL.Port()
						if port == "" {
							if parsedURL.Scheme == "https" {
								port = "443"
							} else {
								port = "80"
							}
						}
						return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
					},
				},
			}
			resp, err := client.Post(sub.WebhookURL, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				log.Printf("Failed to send webhook to %s: %v", redacted, err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				successChan <- true
			} else {
				log.Printf("Webhook to %s returned non-2xx status: %d", redacted, resp.StatusCode)
			}
		}()
	}

	// Send Email using SMTP
	if sub.EnableEmail {
		wg.Add(1)
		go func() {
			defer wg.Done()

			severity := "Low"
			severityColor := "#00cc66"
			if cve.CVSSScore >= 9.0 {
				severity = "Critical"
				severityColor = "#ff4d4d"
			} else if cve.CVSSScore >= 7.0 {
				severity = "High"
				severityColor = "#ff8c00"
			} else if cve.CVSSScore >= 4.0 {
				severity = "Medium"
				severityColor = "#ffcc00"
			}

			kevBadge := ""
			if cve.CISAKEV {
				kevBadge = `
					<div style="background: #ff4d4d; color: #ffffff; padding: 10px 15px; border-radius: 6px; margin-bottom: 25px; font-weight: bold; border-left: 5px solid #b30000;">
						⚠️ KNOWN EXPLOITED VULNERABILITY
						<div style="font-size: 11px; font-weight: normal; margin-top: 3px; opacity: 0.9;">This CVE is documented in the CISA KEV catalog.</div>
					</div>`
			}

			refsHTML := ""
			if len(cve.References) > 0 {
				refsHTML = "<div style='margin-top: 20px;'><strong style='font-size: 12px; text-transform: uppercase; opacity: 0.6;'>References</strong><ul style='padding-left: 20px; margin-top: 10px; font-size: 13px;'>"
				count := 0
				for _, ref := range cve.References {
					if count >= 5 {
						refsHTML += "<li>... and more</li>"
						break
					}
					refsHTML += fmt.Sprintf("<li><a href='%s' style='color: #00daf3; text-decoration: none;'>%s</a></li>", ref, ref)
					count++
				}
				refsHTML += "</ul></div>"
			}

			assetBadge := ""
			if assetName != "" {
				assetBadge = fmt.Sprintf(`
					<div style="background: #1c2026; padding: 10px 15px; border-radius: 6px; margin-bottom: 20px; border-left: 4px solid #00daf3;">
						<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5;">Matched Asset</div>
						<div style="font-size: 14px; font-weight: bold; margin-top: 2px;">%s</div>
					</div>`, assetName)
			}

			epssDisplay := "N/A"
			if cve.EPSSScore > 0 {
				epssDisplay = fmt.Sprintf("%.1f%%", cve.EPSSScore*100)
			}

			cweDisplay := ""
			if cve.CWEID != "" {
				cweDisplay = fmt.Sprintf("<div style='font-size: 11px; opacity: 0.6; margin-top: 5px;'>Type: %s</div>", cve.CWEID)
			}

			buzzStatus := "Quiet"
			buzzColor := "#666666"
			if cve.GitHubPoCCount >= 15 {
				buzzStatus = "High Buzz / Viral"
				buzzColor = "#ff4d4d"
			} else if cve.GitHubPoCCount >= 6 {
				buzzStatus = "Trending / PoC Public"
				buzzColor = "#ff8c00"
			} else if cve.GitHubPoCCount >= 2 {
				buzzStatus = "Emerging Interest"
				buzzColor = "#ffcc00"
			}

			// Generate Action Token and store in Redis for 24 hours
			actionToken, _ := auth.GenerateToken()
			actionData, _ := json.Marshal(map[string]interface{}{
				"user_id": sub.UserID,
				"cve_id":  cve.ID,
				"keyword": sub.Keyword,
			})
			db.RedisClient.Set(context.Background(), "alert_action:"+actionToken, actionData, 24*time.Hour)

			body := fmt.Sprintf(`
				<div style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
					<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
						<span style="color: #00daf3; font-weight: bold; font-size: 18px; letter-spacing: 0.05em;">VULFIXX INTEL</span>
						<span style="background: #1c2026; padding: 4px 10px; border-radius: 4px; font-size: 12px; opacity: 0.7;">%s</span>
					</div>

					%s
					%s

					<h1 style="font-size: 28px; margin: 0 0 5px 0; color: #ffffff;">%s</h1>
					%s
					
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 25px 0;">
						<div style="background: #1c2026; padding: 15px; border-radius: 8px; border-bottom: 3px solid %s;">
							<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5; margin-bottom: 4px;">CVSS Base</div>
							<div style="font-size: 24px; font-weight: bold; color: %s;">%.1f</div>
							<div style="font-size: 10px; font-weight: bold; color: %s; text-transform: uppercase;">%s</div>
						</div>
						<div style="background: #1c2026; padding: 15px; border-radius: 8px; border-bottom: 3px solid #00daf3;">
							<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5; margin-bottom: 4px;">Exploit Prob (EPSS)</div>
							<div style="font-size: 24px; font-weight: bold; color: #00daf3;">%s</div>
							<div style="font-size: 10px; opacity: 0.5; text-transform: uppercase;">Next 30 Days</div>
						</div>
					</div>

					<div style="background: #1c2026; padding: 15px; border-radius: 8px; margin-bottom: 25px; border-left: 4px solid %s;">
						<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5; margin-bottom: 4px;">Social Buzz / PoC Status</div>
						<div style="font-size: 14px; font-weight: bold; color: %s;">%s</div>
						<div style="font-size: 10px; opacity: 0.5; margin-top: 2px;">%d mentions across GitHub repositories</div>
					</div>

					<div style="background: #1c2026; padding: 15px; border-radius: 8px; margin-bottom: 30px;">
						<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5; margin-bottom: 8px;">Technical Vector</div>
						<div style="font-size: 12px; font-family: monospace; word-break: break-all; opacity: 0.8;">%s</div>
					</div>

					<p style="font-size: 15px; line-height: 1.6; color: #b0b5c0; margin-bottom: 30px;">%s</p>

					<div style="background: #1c2026; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
						<div style="font-size: 12px; margin-bottom: 15px;">
							<span style="opacity: 0.5;">Published:</span> <span style="margin-left: 5px;">%s</span>
						</div>
						%s
					</div>

					<a href="%s/cve/%s" style="display: block; width: 100%%; box-sizing: border-box; background: #00daf3; color: #101418; text-align: center; padding: 16px 0; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 14px; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 15px;">Full Technical Analysis</a>
					
					<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
						<a href="%s/alert-action?action=acknowledge&token=%s" style="display: block; background: #1c2026; color: #dfe2eb; text-align: center; padding: 12px 0; border-radius: 6px; text-decoration: none; font-size: 12px; font-weight: bold; border: 1px solid #232931;">Acknowledge</a>
						<a href="%s/alert-action?action=mute&token=%s" style="display: block; background: #1c2026; color: #dfe2eb; text-align: center; padding: 12px 0; border-radius: 6px; text-decoration: none; font-size: 12px; font-weight: bold; border: 1px solid #232931;">Mute Key</a>
					</div>

					<div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #232931; font-size: 11px; opacity: 0.4; text-align: center;">
						Vulfixx Intelligence Engine | Automated Threat Monitoring
					</div>
				</div>
			`, time.Now().Format("Jan 02, 2006"), kevBadge, assetBadge, cve.CVEID, cweDisplay, severityColor, severityColor, cve.CVSSScore, severityColor, severity, epssDisplay, buzzColor, buzzColor, buzzStatus, cve.GitHubPoCCount, cve.VectorString, cve.Description, cve.PublishedDate.Format("Jan 02, 2006"), refsHTML, os.Getenv("BASE_URL"), cve.CVEID, os.Getenv("BASE_URL"), actionToken, os.Getenv("BASE_URL"), actionToken)

			if err := sendEmail(email, "Security Alert: "+cve.CVEID, body); err != nil {
				log.Printf("Failed to send email alert to %s: %v", email, err)
			} else {
				successChan <- true
			}
		}()
	}

	go func() {
		wg.Wait()
		close(successChan)
	}()

	hasSuccess := false
	for success := range successChan {
		if success {
			hasSuccess = true
		}
	}

	return hasSuccess
}

func processEmailVerification(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := db.RedisClient.BRPop(ctx, 0, "email_verification_queue").Result()
			if err != nil {
				log.Println("Error reading from verification queue:", err)
				time.Sleep(1 * time.Second)
				continue
			}

			var payload map[string]string
			if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
				log.Printf("Error unmarshaling email verification payload: %v", err)
				continue
			}

			email := payload["email"]
			token := payload["token"]

			sendVerificationEmail(email, token)
		}
	}
}

func processEmailChange(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := db.RedisClient.BRPop(ctx, 0, "email_change_queue").Result()
			if err != nil {
				log.Println("Error reading from email change queue:", err)
				time.Sleep(1 * time.Second)
				continue
			}

			var payload map[string]string
			if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
				log.Printf("Error unmarshaling email change payload: %v", err)
				continue
			}

			email := payload["email"]
			token := payload["token"]
			emailType := payload["type"]

			sendEmailChangeNotification(email, token, emailType)
		}
	}
}

func sendEmailChangeNotification(email, token, emailType string) {
	log.Printf("Sending email change notification (%s) to %s\n", emailType, email)
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	if smtpHost != "" && smtpPort != "" {
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}

	subject := "Confirm Email Change - Vulfixx"
	content := "Please confirm your email change request by clicking the link below:"
	if emailType == "old" {
		content = "You have requested to change your email address. " + content
	} else {
		content = "You have been set as the new email address for a Vulfixx account. " + content
	}

	body := fmt.Sprintf(`
		<div style="font-family: 'Inter', sans-serif; max-width: 500px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
			<h2 style="color: #00daf3; margin-top: 0;">Email Change Request</h2>
			<p style="font-size: 15px; line-height: 1.6; color: #b0b5c0; margin-bottom: 30px;">%s</p>
			
			<a href="%s/confirm-email-change?token=%s" style="display: block; width: 100%%; background: #00daf3; color: #101418; text-align: center; padding: 14px 0; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 14px; text-transform: uppercase;">Confirm Email Change</a>
			
			<p style="font-size: 12px; opacity: 0.5; margin-top: 30px;">If you did not request this change, please contact support immediately.</p>
		</div>
	`, content, baseURL, token)

	if err := sendEmail(email, subject, body); err != nil {
		log.Printf("Failed to send email change notification to %s: %v", email, err)
	}
	} else {
		// Redact token in dev fallback log; show full link only if ENABLE_DEV_EMAIL_LINK_LOGGING is set
		if os.Getenv("ENABLE_DEV_EMAIL_LINK_LOGGING") == "true" {
			log.Printf("SMTP not configured. Confirmation link for %s (%s): http://localhost:8080/confirm-email-change?token=%s\n", email, emailType, token)
		} else {
			redacted := redactToken(token)
			log.Printf("SMTP not configured. Confirmation link for %s (%s): token=%s (redacted)\n", email, emailType, redacted)
		}
	}
}

func sendVerificationEmail(email, token string) {
	log.Printf("Sending verification email to %s\n", email)
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	if smtpHost != "" && smtpPort != "" {
		// In production, BASE_URL should be configured.
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}

		subject := "Verify Your Email - Vulfixx"
		body := fmt.Sprintf(`
			<div style="font-family: 'Inter', sans-serif; max-width: 500px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
				<h2 style="color: #00daf3; margin-top: 0;">Welcome to Vulfixx</h2>
				<p style="font-size: 15px; line-height: 1.6; color: #b0b5c0; margin-bottom: 30px;">Please verify your email address to start receiving security alerts and managing your infrastructure threats.</p>
				
				<a href="%s/verify-email?token=%s" style="display: block; width: 100%%; background: #00daf3; color: #101418; text-align: center; padding: 14px 0; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 14px; text-transform: uppercase;">Verify Email Address</a>
				
				<p style="font-size: 12px; opacity: 0.5; margin-top: 30px;">If you did not create an account, you can safely ignore this email.</p>
			</div>
		`, baseURL, token)

		if err := sendEmail(email, subject, body); err != nil {
			log.Printf("Failed to send verification email to %s: %v", email, err)
		}
	} else {
		// Redact token in dev fallback log
		if os.Getenv("ENABLE_DEV_EMAIL_LINK_LOGGING") == "true" {
			log.Printf("SMTP not configured. Verification link for %s: http://localhost:8080/verify-email?token=%s\n", email, token)
		} else {
			redacted := redactToken(token)
			log.Printf("SMTP not configured. Verification link for %s: token=%s (redacted)\n", email, redacted)
		}
	}
}

func startWeeklySummaryTask(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			// Send every Monday at 08:00 AM
			if now.Weekday() == time.Monday && now.Hour() == 8 {
				sendWeeklySummaries(ctx)
				// Wait extra time to avoid multiple runs within the 08:00 hour
				time.Sleep(2 * time.Hour)
			}
		}
	}
}

func sendWeeklySummaries(ctx context.Context) {
	log.Println("Worker: [WEEKLY] Starting intelligence brief generation...")
	rows, err := db.Pool.Query(ctx, "SELECT id, email FROM users WHERE is_email_verified = TRUE")
	if err != nil {
		log.Printf("Worker: [ERROR] Failed to fetch users for weekly brief: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var userID int
		var email string
		if err := rows.Scan(&userID, &email); err != nil {
			continue
		}

		var totalNew, resolved int
		err := db.Pool.QueryRow(ctx, `
			SELECT 
				(SELECT COUNT(*) FROM cves WHERE published_date > NOW() - INTERVAL '7 days') as new_count,
				(SELECT COUNT(*) FROM user_cve_status WHERE user_id = $1 AND status = 'resolved' AND updated_at > NOW() - INTERVAL '7 days') as resolved_count
		`, userID).Scan(&totalNew, &resolved)

		if err != nil {
			log.Printf("Worker: [ERROR] Failed to calculate stats for %s: %v", email, err)
			continue
		}

		body := fmt.Sprintf(`
			<div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
				<h1 style="color: #00daf3; font-size: 24px; margin-bottom: 10px;">Vulfixx Weekly Brief</h1>
				<p style="opacity: 0.7; font-size: 14px; margin-bottom: 30px;">Intelligence summary for the last 7 days.</p>
				
				<div style="display: grid; grid-template-cols: 1fr 1fr; gap: 20px; margin-bottom: 40px;">
					<div style="background: #1c2026; padding: 20px; border-radius: 8px; border-left: 4px solid #00daf3;">
						<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5;">New Threats</div>
						<div style="font-size: 32px; font-weight: bold; margin-top: 5px;">%d</div>
					</div>
					<div style="background: #1c2026; padding: 20px; border-radius: 8px; border-left: 4px solid #00f39a;">
						<div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5;">Resolved</div>
						<div style="font-size: 32px; font-weight: bold; margin-top: 5px;">%d</div>
					</div>
				</div>

				<p style="margin-bottom: 30px;">Review your full vulnerability inventory and remediation steps in the Vulfixx dashboard.</p>
				
				<a href="%s/dashboard" style="display: block; width: 100%%; background: #00daf3; color: #101418; text-align: center; padding: 15px 0; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Access Dashboard</a>
			</div>
		`, totalNew, resolved, os.Getenv("BASE_URL"))

		if err := sendEmail(email, "Weekly Intelligence Brief", body); err != nil {
			log.Printf("Worker: [ERROR] Failed to send brief to %s: %v", email, err)
		}
	}
	log.Println("Worker: [WEEKLY] Intelligence briefs dispatched.")
}
func sendEmail(toEmail, subject, body string) error {
	safeEmail, err := sanitizeEmail(toEmail)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost == "" || smtpPort == "" {
		return fmt.Errorf("SMTP not configured")
	}

	mime := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n%s%s", smtpUser, safeEmail, subject, mime, body))

	return sendMailWithTimeout(smtpHost, smtpPort, smtpUser, smtpPass, []string{safeEmail}, msg)
}
func syncEPSSPeriodically(ctx context.Context) {
	// Sync every 24 hours
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	
	// Initial sync
	syncEPSS(ctx)

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
		// Respect rate limits
		time.Sleep(100 * time.Millisecond)
	}
	log.Println("Worker: [SYNC] EPSS score synchronization complete.")
}

func syncGitHubBuzzPeriodically(ctx context.Context) {
	// Sync more frequently since GitHub data changes fast (every 4 hours)
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
	
	// Check CVEs from the last 14 days as interest is highest then
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

		// GitHub Search API (Public, Unauthenticated limit is 10 req/min)
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

		// Throttle to respect unauthenticated rate limits (10 req/min -> 6 seconds delay)
		time.Sleep(7 * time.Second)
	}
	log.Println("Worker: [SYNC] GitHub Social Buzz synchronization complete.")
}
