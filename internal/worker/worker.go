package worker

import (
	"context"
	"crypto/tls"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
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
	defer func() { _ = resp.Body.Close() }()

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

		cve := models.CVE{
			CVEID:         cveData.ID,
			Description:   desc,
			CVSSScore:     score,
			VectorString:  vector,
			PublishedDate: pubDate,
			UpdatedDate:   modDate,
		}

		var id int
		var tag string
		err := db.Pool.QueryRow(ctx, `
			WITH upsert AS (
				INSERT INTO cves (cve_id, description, cvss_score, vector_string, "references", published_date, updated_date)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (cve_id) DO UPDATE SET
					description = EXCLUDED.description,
					cvss_score = EXCLUDED.cvss_score,
					vector_string = EXCLUDED.vector_string,
					"references" = EXCLUDED."references",
					updated_date = EXCLUDED.updated_date
				RETURNING id, (xmax = 0) AS is_insert
			)
			SELECT id, CASE WHEN is_insert THEN 'ins' ELSE 'upd' END FROM upsert
		`, cve.CVEID, cve.Description, cve.CVSSScore, cve.VectorString, refs, cve.PublishedDate, cve.UpdatedDate).Scan(&id, &tag)

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
			if notifyIfNew(ctx, sub.UserID, cve.ID, sub, email) {
				notifiedUsers[sub.UserID] = true
			}
		}
	}

	// Asset-Linked Monitoring (Virtual Subscriptions)
	assetRows, err := db.Pool.Query(ctx, `
		SELECT ak.keyword, a.user_id, u.email
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
		var keyword, email string
		var userID int
		if err := assetRows.Scan(&keyword, &userID, &email); err != nil {
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
			if notifyIfNew(ctx, userID, cve.ID, sub, email) {
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

func notifyIfNew(ctx context.Context, userID, cveID int, sub models.UserSubscription, email string) bool {
	var exists bool
	if err := db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM alert_history WHERE user_id=$1 AND cve_id=$2)", userID, cveID).Scan(&exists); err != nil {
		return false
	}
	if exists {
		return false
	}

	// Fetch CVE for alert
	var cve models.CVE
	err := db.Pool.QueryRow(ctx, "SELECT cve_id, description, cvss_score FROM cves WHERE id = $1", cveID).Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore)
	if err != nil {
		return false
	}

	if sendAlert(sub, &cve, email) {
		_, _ = db.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id) VALUES ($1, $2)", userID, cveID)
		return true
	}
	return false
}

func sendWebhookAlert(sub models.UserSubscription, cve *models.CVE, email string) bool {
	u, err := url.Parse(sub.WebhookURL)
	if err != nil {
		log.Printf("Invalid webhook URL for %s: %v", email, err)
		return false
	}

	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", u.Hostname())
	if err != nil {
		log.Printf("DNS resolution failed for webhook %s: %v", redactURL(sub.WebhookURL), err)
		return false
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			log.Printf("Blocked webhook to unsafe IP %s for %s", ip.String(), email)
			return false
		}
	}

	payload := map[string]interface{}{
		"cve_id":      cve.CVEID,
		"description": cve.Description,
		"cvss_score":  cve.CVSSScore,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal webhook payload: %v", err)
		return false
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", sub.WebhookURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send webhook to %s: %v", redactURL(sub.WebhookURL), err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func sendEmailAlert(cve *models.CVE, email string) bool {
	subject := fmt.Sprintf("Vulfixx Alert: %s", cve.CVEID)
	body := fmt.Sprintf(`
		<div style="font-family: 'Inter', sans-serif; padding: 20px;">
			<h2 style="color: #ff4a4a;">New Vulnerability Alert</h2>
			<p><strong>CVE ID:</strong> %s</p>
			<p><strong>CVSS Score:</strong> %.1f</p>
			<p><strong>Description:</strong> %s</p>
		</div>
	`, cve.CVEID, cve.CVSSScore, cve.Description)

	err := sendEmail(email, subject, body)
	if err != nil {
		log.Printf("Failed to send email alert to %s: %v", email, err)
		return false
	}
	return true
}

func sendAlert(sub models.UserSubscription, cve *models.CVE, email string) bool {
	log.Printf("ALERT: Sending to %s for %s\n", email, cve.CVEID)

	var wg sync.WaitGroup
	successChan := make(chan bool, 2)

	if sub.EnableWebhook && sub.WebhookURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sendWebhookAlert(sub, cve, email) {
				successChan <- true
			}
		}()
	}

	// Send Email using SMTP
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	if sub.EnableEmail && smtpHost != "" && smtpPort != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sendEmailAlert(cve, email) {
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
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost != "" && smtpPort != "" {
		safeEmail, emailErr := sanitizeEmail(email)
		if emailErr != nil {
			log.Printf("Invalid email for email change notification: %v", emailErr)
			return
		}
		to := []string{safeEmail}
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}

		subject := "Confirm Email Change - CVE Tracker"
		body := fmt.Sprintf("Please confirm your email change request by clicking the link below:\r\n\r\n"+
			"%s/confirm-email-change?token=%s\r\n", baseURL, token)

		if emailType == "old" {
			body = "You have requested to change your email address. " + body
		} else {
			body = "You have been set as the new email address for a CVE Tracker account. " + body
		}

		msg := []byte(fmt.Sprintf("From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n"+
			"%s", smtpUser, safeEmail, subject, body))

		err := sendMailWithTimeout(smtpHost, smtpPort, smtpUser, smtpPass, to, msg) // #nosec G707 -- email validated above
		if err != nil {
			log.Printf("Failed to send email change notification to %s: %v", safeEmail, err)
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
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost != "" && smtpPort != "" {
		safeEmail, emailErr := sanitizeEmail(email)
		if emailErr != nil {
			log.Printf("Invalid email for verification: %v", emailErr)
			return
		}
		to := []string{safeEmail}
		// In production, BASE_URL should be configured.
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}

		msg := []byte(fmt.Sprintf("From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: Verify Your Email - CVE Tracker\r\n"+
			"\r\n"+
			"Please verify your email address by clicking the link below:\r\n\r\n"+
			"%s/verify-email?token=%s\r\n", smtpUser, safeEmail, baseURL, token))

		err := sendMailWithTimeout(smtpHost, smtpPort, smtpUser, smtpPass, to, msg) // #nosec G707 -- email validated above
		if err != nil {
			log.Printf("Failed to send verification email to %s: %v", safeEmail, err)
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

	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n%s%s", smtpUser, safeEmail, subject, mime, body))

	return sendMailWithTimeout(smtpHost, smtpPort, smtpUser, smtpPass, []string{safeEmail}, msg)
}
