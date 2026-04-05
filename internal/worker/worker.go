package worker

import (
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
	go fetchCVEsPeriodically()
	go processAlerts()
	go processEmailVerification()
}

func fetchCVEsPeriodically() {
	ticker := time.NewTicker(1 * time.Minute) // In prod, maybe every hour
	defer ticker.Stop()

	for {
		log.Println("Worker: Fetching CVEs...")
		// Simulated NVD fetch (stub)
		// In a real app, make HTTP GET to https://services.nvd.nist.gov/rest/json/cves/2.0
		cves := []models.CVE{
			{CVEID: fmt.Sprintf("CVE-2024-%d", time.Now().Unix()%10000), Description: "A simulated vulnerability in Fortigate firewalls allowing RCE.", CVSSScore: 9.8, CISAKEV: true, PublishedDate: time.Now(), UpdatedDate: time.Now()},
			{CVEID: fmt.Sprintf("CVE-2024-%d", (time.Now().Unix()+1)%10000), Description: "A simulated vulnerability in Spring Boot.", CVSSScore: 7.5, CISAKEV: false, PublishedDate: time.Now(), UpdatedDate: time.Now()},
		}

		ctx := context.Background()
		for _, cve := range cves {
			var id int
			err := db.Pool.QueryRow(ctx, `
				INSERT INTO cves (cve_id, description, cvss_score, cisa_kev, published_date, updated_date)
				VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (cve_id) DO UPDATE SET
					description = EXCLUDED.description,
					cvss_score = EXCLUDED.cvss_score,
					cisa_kev = EXCLUDED.cisa_kev,
					updated_date = EXCLUDED.updated_date
				RETURNING id
			`, cve.CVEID, cve.Description, cve.CVSSScore, cve.CISAKEV, cve.PublishedDate, cve.UpdatedDate).Scan(&id)

			if err != nil {
				log.Println("Error upserting CVE:", err)
				continue
			}
			cve.ID = id
			// Queue alert processing
			alertJob, _ := json.Marshal(cve)
			db.RedisClient.LPush(ctx, "cve_alerts_queue", alertJob)
		}

		<-ticker.C
	}
}

func processAlerts() {
	ctx := context.Background()
	for {
		result, err := db.RedisClient.BRPop(ctx, 0, "cve_alerts_queue").Result()
		if err != nil {
			log.Println("Error reading from queue:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var cve models.CVE
		json.Unmarshal([]byte(result[1]), &cve)

		evaluateSubscriptions(ctx, &cve)
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
		rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity, &sub.WebhookURL, &email)

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
			db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM alert_history WHERE user_id=$1 AND cve_id=$2)", sub.UserID, cve.ID).Scan(&exists)
			if !exists {
				// Send alert
				sendAlert(sub, cve, email)
				// Record history
				db.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id) VALUES ($1, $2)", sub.UserID, cve.ID)
			}
		}
	}
}

func sendAlert(sub models.UserSubscription, cve *models.CVE, email string) {
	log.Printf("ALERT: Sending to %s for %s\n", email, cve.CVEID)
	// If webhook URL is set, send POST request
	if sub.WebhookURL != "" {
		if !strings.HasPrefix(sub.WebhookURL, "http://") && !strings.HasPrefix(sub.WebhookURL, "https://") {
			log.Printf("Skipping invalid webhook URL: %s", sub.WebhookURL)
		} else {
			payload, _ := json.Marshal(map[string]interface{}{
				"cve_id": cve.CVEID,
				"description": cve.Description,
				"cvss_score": cve.CVSSScore,
				"user_email": email,
			})
			go func() {
				resp, err := http.Post(sub.WebhookURL, "application/json", bytes.NewBuffer(payload))
				if err == nil {
					defer resp.Body.Close()
				} else {
					log.Printf("Failed to send webhook to %s: %v", sub.WebhookURL, err)
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


func processEmailVerification() {
	ctx := context.Background()
	for {
		result, err := db.RedisClient.BRPop(ctx, 0, "email_verification_queue").Result()
		if err != nil {
			log.Println("Error reading from verification queue:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var payload map[string]string
		json.Unmarshal([]byte(result[1]), &payload)

		email := payload["email"]
		token := payload["token"]

		sendVerificationEmail(email, token)
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