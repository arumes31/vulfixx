package worker

import (
	"net/netip"
	"net/url"
	"net"
	"bytes"
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

func StartWorker() {
	ctx := context.Background()
	go fetchCVEsPeriodically()
	go processAlerts(ctx)
	go processEmailVerification(ctx)
	go processEmailChange(ctx)
}

type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Published   string `json:"published"`
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
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func fetchCVEsPeriodically() {
	// NIST NVD rate limit is strict. Using 1 hour here for real usage.
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Fetch immediately on startup
	fetchFromNVD()

	for {
		<-ticker.C
		fetchFromNVD()
	}
}

func fetchFromNVD() {
	log.Println("Worker: Fetching CVEs from NVD...")
	// We'll fetch the latest modified CVEs from the last hour or so.
	// For simplicity, we just fetch a recent chunk without date parameters,
	// but normally you'd use 'pubStartDate' and 'pubEndDate'.

	baseURL := os.Getenv("NVD_API_URL")
	if baseURL == "" {
		baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	url := baseURL + "?resultsPerPage=50"

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println("Error creating NVD request:", err)
		return
	}
	// Add API key if available to avoid rate limits
	if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error fetching from NVD:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.Printf("NVD API returned status: %d", resp.StatusCode)
		return
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		log.Println("Error decoding NVD response:", err)
		return
	}

	ctx := context.Background()
	for _, v := range nvdResp.Vulnerabilities {
		cveData := v.CVE

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
		err := db.Pool.QueryRow(ctx, `
			INSERT INTO cves (cve_id, description, cvss_score, published_date, updated_date)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (cve_id) DO UPDATE SET
				description = EXCLUDED.description,
				cvss_score = EXCLUDED.cvss_score,
				updated_date = EXCLUDED.updated_date
			RETURNING id
		`, cve.CVEID, cve.Description, cve.CVSSScore, cve.PublishedDate, cve.UpdatedDate).Scan(&id)

		if err != nil {
			// Row may exist but unchanged or other err, ignore
			continue
		}
		cve.ID = id

		alertJob, _ := json.Marshal(cve)
		db.RedisClient.LPush(ctx, "cve_alerts_queue", alertJob)
	}
	log.Println("Worker: NVD fetch complete.")
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
		SELECT s.id, s.user_id, s.keyword, s.min_severity, s.webhook_url, u.email
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
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity, &sub.WebhookURL, &email); err != nil {
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
				// Send alert
				sendAlert(sub, cve, email)
				// Record history
				if _, err := db.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id) VALUES ($1, $2)", sub.UserID, cve.ID); err != nil {
					log.Printf("Error recording alert history: %v", err)
				}
			}
		}
	}
}

func sendAlert(sub models.UserSubscription, cve *models.CVE, email string) {
	log.Printf("ALERT: Sending to %s for %s\n", email, cve.CVEID)
	if sub.WebhookURL != "" {
		parsedURL, err := url.Parse(sub.WebhookURL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			log.Printf("Skipping invalid webhook URL scheme: %s", sub.WebhookURL)
		} else {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, parsedURL.Hostname())
				if err != nil {
					log.Printf("Failed to resolve webhook host: %s, err: %v", sub.WebhookURL, err)
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
					log.Printf("Skipping unsafe webhook URL IP: %s", sub.WebhookURL)
				} else {
					payload, _ := json.Marshal(map[string]interface{}{
						"cve_id": cve.CVEID,
						"description": cve.Description,
						"cvss_score": cve.CVSSScore,
						"user_email": email,
					})
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
					if err == nil {
						defer func() { _ = resp.Body.Close() }()
					} else {
						log.Printf("Failed to send webhook to %s: %v", sub.WebhookURL, err)
					}
				}
			}()
		}
	}

	// Send Email using SMTP
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost != "" && smtpPort != "" {
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		to := []string{email}
		msg := []byte(fmt.Sprintf("To: %s\r\n"+
			"Subject: New CVE Alert: %s\r\n"+
			"\r\n"+
			"A new CVE matching your subscription has been found.\r\n\r\n"+
			"CVE ID: %s\r\n"+
			"CVSS Score: %.1f\r\n"+
			"Description: %s\r\n", email, cve.CVEID, cve.CVEID, cve.CVSSScore, cve.Description))

		go func() {
			err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, to, msg)
			if err != nil {
				log.Printf("Failed to send email to %s: %v", email, err)
			}
		}()
	}
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
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		to := []string{email}
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

		msg := []byte(fmt.Sprintf("To: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n"+
			"%s", email, subject, body))

		err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, to, msg)
		if err != nil {
			log.Printf("Failed to send email change notification to %s: %v", email, err)
		}
	} else {
		log.Printf("SMTP not configured. Confirmation link for %s (%s): http://localhost:8080/confirm-email-change?token=%s\n", email, emailType, token)
	}
}

func sendVerificationEmail(email, token string) {
	log.Printf("Sending verification email to %s\n", email)
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost != "" && smtpPort != "" {
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		to := []string{email}
		// In production, BASE_URL should be configured.
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}

		msg := []byte(fmt.Sprintf("To: %s\r\n"+
			"Subject: Verify Your Email - CVE Tracker\r\n"+
			"\r\n"+
			"Please verify your email address by clicking the link below:\r\n\r\n"+
			"%s/verify-email?token=%s\r\n", email, baseURL, token))

		err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, to, msg)
		if err != nil {
			log.Printf("Failed to send verification email to %s: %v", email, err)
		}
	} else {
		log.Printf("SMTP not configured. Verification link for %s: http://localhost:8080/verify-email?token=%s\n", email, token)
	}
}