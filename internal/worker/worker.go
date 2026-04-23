package worker

import (
	"bytes"
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
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
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

		req, err := http.NewRequestWithContext(ctx, "GET", nvdURL, nil)
		if err != nil {
			log.Println("Error creating NVD request:", err)
			return
		}
		if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Println("Error fetching from NVD:", err)
			time.Sleep(delay * 2)
			continue
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			log.Printf("Worker: NVD rate-limited (HTTP %d), backing off...", resp.StatusCode)
			time.Sleep(30 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("NVD API returned status: %d", resp.StatusCode)
			return
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			resp.Body.Close()
			log.Println("Error decoding NVD response:", err)
			return
		}
		resp.Body.Close()

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
		Metrics struct {
			CvssMetricV31 []struct {
				CvssData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CvssMetricV30 []struct {
				CvssData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV30"`
			CvssMetricV2 []struct {
				CvssData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
	} `json:"cve"`
}, sendAlerts bool) (inserted int, updated int) {
	for _, v := range vulnerabilities {
		cveData := v.CVE
		// ... logic continues

		desc := ""
		for _, d := range cveData.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		score := 0.0
		if len(cveData.Metrics.CvssMetricV31) > 0 {
			score = cveData.Metrics.CvssMetricV31[0].CvssData.BaseScore
		} else if len(cveData.Metrics.CvssMetricV30) > 0 {
			score = cveData.Metrics.CvssMetricV30[0].CvssData.BaseScore
		} else if len(cveData.Metrics.CvssMetricV2) > 0 {
			score = cveData.Metrics.CvssMetricV2[0].CvssData.BaseScore
		}

		pubDate, _ := time.Parse(time.RFC3339, cveData.Published)
		modDate, _ := time.Parse(time.RFC3339, cveData.LastModified)

		cve := models.CVE{
			CVEID:         cveData.ID,
			Description:   desc,
			CVSSScore:     score,
			PublishedDate: pubDate,
			UpdatedDate:   modDate,
		}

		var id int
		var tag string
		err := db.Pool.QueryRow(ctx, `
			WITH upsert AS (
				INSERT INTO cves (cve_id, description, cvss_score, published_date, updated_date)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (cve_id) DO UPDATE SET
					description = EXCLUDED.description,
					cvss_score = EXCLUDED.cvss_score,
					updated_date = EXCLUDED.updated_date
				RETURNING id, (xmax = 0) AS is_insert
			)
			SELECT id, CASE WHEN is_insert THEN 'ins' ELSE 'upd' END FROM upsert
		`, cve.CVEID, cve.Description, cve.CVSSScore, cve.PublishedDate, cve.UpdatedDate).Scan(&id, &tag)

		if err == nil {
			if tag == "ins" {
				inserted++
			} else {
				updated++
			}
		} else {
			// fallback for identical rows or errors
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
	// Find matching subscriptions
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

	for rows.Next() {
		var sub models.UserSubscription
		var email string
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity, &sub.WebhookURL, &sub.EnableEmail, &sub.EnableWebhook, &email); err != nil {
			log.Printf("Error scanning subscription row: %v", err)
			continue
		}

		// Basic matching
		match := true
		if sub.Keyword != "" && !strings.Contains(strings.ToLower(cve.Description), strings.ToLower(sub.Keyword)) {
			match = false
		}
		if sub.MinSeverity > 0 && cve.CVSSScore < sub.MinSeverity {
			match = false
		}

		if match {
			// Check if already alerted
			var exists bool
			if err := db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM alert_history WHERE user_id=$1 AND cve_id=$2)", sub.UserID, cve.ID).Scan(&exists); err != nil {
				log.Printf("Error checking alert history: %v", err)
				continue
			}
			if !exists {
				// Send alert and only record history on success
				success := sendAlert(sub, cve, email)
				if success {
					if _, err := db.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id) VALUES ($1, $2)", sub.UserID, cve.ID); err != nil {
						log.Printf("Error recording alert history: %v", err)
					}
				} else {
					log.Printf("Warning: all alert deliveries failed for user %d, CVE %s — not recording history", sub.UserID, cve.CVEID)
				}
			}
		}
	}
}

func sendAlert(sub models.UserSubscription, cve *models.CVE, email string) bool {
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
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if sub.EnableEmail && smtpHost != "" && smtpPort != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			safeEmail, emailErr := sanitizeEmail(email)
			if emailErr != nil {
				log.Printf("Invalid email for CVE alert: %v", emailErr)
				return
			}
			to := []string{safeEmail}
			msg := []byte(fmt.Sprintf("From: %s\r\n"+
				"To: %s\r\n"+
				"Subject: New CVE Alert: %s\r\n"+
				"\r\n"+
				"A new CVE matching your subscription has been found.\r\n\r\n"+
				"CVE ID: %s\r\n"+
				"CVSS Score: %.1f\r\n"+
				"Description: %s\r\n", smtpUser, safeEmail, cve.CVEID, cve.CVEID, cve.CVSSScore, cve.Description))

			err := sendMailWithTimeout(smtpHost, smtpPort, smtpUser, smtpPass, to, msg) // #nosec G707 -- email sanitized above
			if err != nil {
				log.Printf("Failed to send email to %s: %v", email, err)
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
