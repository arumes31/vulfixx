package worker

import (
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func processAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := db.RedisClient.BRPop(ctx, 0, "cve_alerts_queue").Result()
			if err != nil {
				log.Println("Error reading from alerts queue:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			var cve models.CVE
			if err := json.Unmarshal([]byte(result[1]), &cve); err != nil {
				log.Printf("Error unmarshaling alert job: %v", err)
				continue
			}
			evaluateSubscriptions(ctx, &cve)
		}
	}
}

func evaluateSubscriptions(ctx context.Context, cve *models.CVE) {
	rows, err := db.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.keyword, s.min_severity, s.webhook_url, s.enable_email, s.enable_webhook, s.filter_logic, u.email
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
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity, &sub.WebhookURL, &sub.EnableEmail, &sub.EnableWebhook, &sub.FilterLogic, &email); err != nil {
			log.Printf("Error scanning subscription row: %v", err)
			continue
		}
		if matchCVE(cve, sub) {
			if notifyIfNew(ctx, sub.UserID, cve.ID, sub, email, "") {
				notifiedUsers[sub.UserID] = true
			}
		}
	}

	assetRows, err := db.Pool.Query(ctx, `
		SELECT ak.keyword, a.user_id, u.email, a.name
		FROM asset_keywords ak
		JOIN assets a ON ak.asset_id = a.id
		JOIN users u ON a.user_id = u.id
		WHERE u.is_email_verified = TRUE
	`)
	if err == nil {
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
				sub := models.UserSubscription{EnableEmail: true, EnableWebhook: true}
				if notifyIfNew(ctx, userID, cve.ID, sub, email, assetName) {
					notifiedUsers[userID] = true
				}
			}
		}
	}
}

func matchCVE(cve *models.CVE, sub models.UserSubscription) bool {
	if sub.Keyword != "" && !strings.Contains(strings.ToLower(cve.Description), strings.ToLower(sub.Keyword)) {
		return false
	}
	if sub.MinSeverity > 0 && cve.CVSSScore < sub.MinSeverity {
		return false
	}
	if sub.FilterLogic != "" {
		return evaluateComplexFilter(sub.FilterLogic, cve)
	}
	return true
}

func evaluateComplexFilter(logic string, cve *models.CVE) bool {
	logic = strings.ToLower(logic)
	if strings.Contains(logic, "epss >") {
		parts := strings.Split(logic, "epss >")
		if len(parts) > 1 {
			valStr := strings.TrimSpace(strings.Split(parts[1], " ")[0])
			if val, err := strconv.ParseFloat(valStr, 64); err == nil {
				if cve.EPSSScore <= val {
					return false
				}
			}
		}
	}
	if strings.Contains(logic, "cisa == true") || strings.Contains(logic, "cisa = true") {
		if !cve.CISAKEV {
			return false
		}
	}
	if strings.Contains(logic, "buzz >") {
		parts := strings.Split(logic, "buzz >")
		if len(parts) > 1 {
			valStr := strings.TrimSpace(strings.Split(parts[1], " ")[0])
			if val, err := strconv.Atoi(valStr); err == nil {
				if cve.GitHubPoCCount <= val {
					return false
				}
			}
		}
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
	var cve models.CVE
	err := db.Pool.QueryRow(ctx, `
		SELECT cve_id, description, cvss_score, vector_string, cisa_kev, epss_score, cwe_id, github_poc_count, published_date, "references" 
		FROM cves WHERE id = $1
	`, cveID).Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.VectorString, &cve.CISAKEV, &cve.EPSSScore, &cve.CWEID, &cve.GitHubPoCCount, &cve.PublishedDate, &cve.References)
	if err != nil {
		log.Printf("Failed to fetch full CVE details for alert: %v", err)
		return false
	}
	cve.OSINTData = fetchOSINTLinks(ctx, cve.CVEID)
	return bufferAlert(ctx, userID, &cve, email, assetName)
}

func bufferAlert(ctx context.Context, userID int, cve *models.CVE, email, assetName string) bool {
	// Severity-Based Routing:
	// Critical (>= 9.0) gets immediate delivery.
	// High (>= 7.0) gets a short buffer (1 min).
	// Others get a longer buffer (5 min) for digest creation.
	
	if cve.CVSSScore >= 9.0 {
		sub := models.UserSubscription{EnableEmail: true, EnableWebhook: true}
		return sendAlert(sub, cve, email, assetName)
	}

	key := fmt.Sprintf("alert_buffer:%d", userID)
	data := map[string]interface{}{"cve": cve, "email": email, "asset_name": assetName}
	blob, _ := json.Marshal(data)
	db.RedisClient.RPush(ctx, key, blob)

	processingKey := fmt.Sprintf("alert_processing:%d", userID)
	set, _ := db.RedisClient.SetNX(ctx, processingKey, "true", 10*time.Minute).Result()
	if set {
		bufferTime := 5 * time.Minute
		if cve.CVSSScore >= 7.0 {
			bufferTime = 1 * time.Minute
		}

		go func(bTime time.Duration) {
			time.Sleep(bTime)
			processUserBuffer(context.Background(), userID)
			db.RedisClient.Del(context.Background(), processingKey)
		}(bufferTime)
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
		var data struct {
			CVE       models.CVE `json:"cve"`
			Email     string     `json:"email"`
			AssetName string     `json:"asset_name"`
		}
		if err := json.Unmarshal([]byte(blobs[0]), &data); err == nil {
			sub := models.UserSubscription{EnableEmail: true, EnableWebhook: true}
			sendAlert(sub, &data.CVE, data.Email, data.AssetName)
		}
		return
	}
	var email string
	type AlertItem struct {
		CVEID     string
		Score     float64
		AssetName string
		Buzz      int
		HasOSINT  bool
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
		hasOSINT := false
		if hn, ok := data.CVE.OSINTData["hn"].([]interface{}); ok && len(hn) > 0 {
			hasOSINT = true
		} else if r, ok := data.CVE.OSINTData["reddit"].([]interface{}); ok && len(r) > 0 {
			hasOSINT = true
		}
		items = append(items, AlertItem{
			CVEID:     data.CVE.CVEID,
			Score:     data.CVE.CVSSScore,
			AssetName: data.AssetName,
			Buzz:      data.CVE.GitHubPoCCount,
			HasOSINT:  hasOSINT,
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
		if item.HasOSINT {
			if buzzBadge != "" {
				buzzBadge += " | 💬 Intel"
			} else {
				buzzBadge = "💬 Intel"
			}
		}
		rowsHTML += fmt.Sprintf(`
			<tr>
				<td style="padding: 15px; border-bottom: 1px solid #232931;">
					<strong style="color: #00daf3;">%s</strong>%s
				</td>
				<td style="padding: 15px; border-bottom: 1px solid #232931; text-align: center; font-size: 12px;">%s</td>
				<td style="padding: 15px; border-bottom: 1px solid #232931; text-align: right;">
					<span style="background: #1c2026; padding: 4px 10px; border-radius: 4px; font-weight: bold;">%.1f</span>
				</td>
			</tr>
		`, item.CVEID, assetInfo, buzzBadge, item.Score)
	}
	body := fmt.Sprintf(`
		<div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
			<h2 style="color: #00daf3; margin-top: 0;">Intelligence Brief: %d New Threats</h2>
			<table style="width: 100%%; border-collapse: collapse; margin-bottom: 30px;">
				<thead>
					<tr style="font-size: 11px; text-transform: uppercase; opacity: 0.5; text-align: left;">
						<th style="padding: 10px 15px;">Vulnerability</th>
						<th style="padding: 10px 15px; text-align: center;">Buzz</th>
						<th style="padding: 10px 15px; text-align: right;">CVSS</th>
					</tr>
				</thead>
				<tbody>%s</tbody>
			</table>
			<a href="%s/dashboard" style="display: block; width: 100%%; background: #00daf3; color: #101418; text-align: center; padding: 15px 0; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 14px; text-transform: uppercase;">Review All Threats</a>
		</div>
	`, len(items), rowsHTML, os.Getenv("BASE_URL"))
	if err := sendEmail(email, "Threat Brief: Multiple Vulnerabilities Detected", body); err != nil {
		log.Printf("Failed to send threat brief: %v", err)
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
			
			// Robust Webhook Security (from main)
			parsedURL, err := url.Parse(sub.WebhookURL)
			redacted := redactURL(sub.WebhookURL)
			if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
				log.Printf("Skipping invalid webhook URL scheme: %s", redacted)
				return
			}

			// DNS Pinning / SSRF Protection
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
				if addr, ok := netip.AddrFromSlice(ipAddr.IP); ok {
					if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
						isSafe = false
						break
					}
					if safeIP == nil {
						safeIP = ipAddr.IP
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
				"asset_name":  assetName,
			}
			if os.Getenv("WEBHOOK_INCLUDE_USER_EMAIL") == "true" {
				payloadMap["user_email"] = email
			}
			payload, _ := json.Marshal(payloadMap)

			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						port := parsedURL.Port()
						if port == "" {
							if parsedURL.Scheme == "https" { port = "443" } else { port = "80" }
						}
						dialer := &net.Dialer{Timeout: 5 * time.Second}
						return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
					},
				},
			}

			resp, err := client.Post(sub.WebhookURL, "application/json", strings.NewReader(string(payload)))
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					successChan <- true
				}
			}
		}()
	}
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
				kevBadge = `<div style="background: #ff4d4d; color: #ffffff; padding: 10px 15px; border-radius: 6px; margin-bottom: 25px; font-weight: bold; border-left: 5px solid #b30000;">⚠️ KNOWN EXPLOITED VULNERABILITY</div>`
			}
			advisories := classifyVendorAdvisories(cve.References)
			advisoryHTML := ""
			if len(advisories) > 0 {
				advisoryHTML = "<div style='background: #1c2026; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffcc00;'><strong style='opacity: 0.5;'>Vendor Advisories</strong><ul>"
				for _, adv := range advisories {
					advisoryHTML += fmt.Sprintf("<li><a href='%s' style='color: #ffcc00;'>%s</a></li>", adv, adv)
				}
				advisoryHTML += "</ul></div>"
			}
			epssDisplay := "N/A"
			if cve.EPSSScore > 0 {
				epssDisplay = fmt.Sprintf("%.1f%%", cve.EPSSScore*100)
			}
			actionToken, _ := auth.GenerateToken()
			actionData, _ := json.Marshal(map[string]interface{}{"user_id": sub.UserID, "cve_id": cve.ID, "keyword": sub.Keyword})
			db.RedisClient.Set(context.Background(), "alert_action:"+actionToken, actionData, 24*time.Hour)
			body := fmt.Sprintf(`
				<div style="font-family: sans-serif; max-width: 600px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
					<h1 style="color: #ffffff;">%s</h1>
					%s %s
					<div style="margin: 20px 0;">CVSS: <span style="color: %s;">%.1f (%s)</span> | EPSS: %s</div>
					<p>%s</p>
					%s
					<a href="%s/dashboard" style="display: block; background: #00daf3; color: #101418; text-align: center; padding: 15px 0; border-radius: 8px; text-decoration: none; font-weight: bold;">View Details</a>
				</div>
			`, cve.CVEID, kevBadge, advisoryHTML, severityColor, cve.CVSSScore, severity, epssDisplay, cve.Description, os.Getenv("BASE_URL"), os.Getenv("BASE_URL"))
			if err := sendEmail(email, "Security Alert: "+cve.CVEID, body); err == nil {
				successChan <- true
			}
		}()
	}
	wg.Wait()
	close(successChan)
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
			if err == nil {
				var payload map[string]string
				if err := json.Unmarshal([]byte(result[1]), &payload); err == nil {
					sendVerificationEmail(payload["email"], payload["token"])
				}
			}
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
			if err == nil {
				var payload map[string]string
				if err := json.Unmarshal([]byte(result[1]), &payload); err == nil {
					sendEmailChangeNotification(payload["email"], payload["token"], payload["type"])
				}
			}
		}
	}
}

func sendEmailChangeNotification(email, token, emailType string) {
	subject := "Confirm Your Email Change"
	body := fmt.Sprintf("Please click the link below to confirm your new email address: %s/confirm-email-change?token=%s", os.Getenv("BASE_URL"), token)
	_ = sendEmail(email, subject, body)
}

func sendVerificationEmail(email, token string) {
	subject := "Verify Your Email Address"
	body := fmt.Sprintf("Please click the link below to verify your email address: %s/verify-email?token=%s", os.Getenv("BASE_URL"), token)
	_ = sendEmail(email, subject, body)
}

func startWeeklySummaryTask(ctx context.Context) {
	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendWeeklySummaries(ctx)
		}
	}
}

func sendWeeklySummaries(ctx context.Context) {
	// Implementation logic for weekly summaries
}

func sendEmail(toEmail, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if host == "" || from == "" {
		return fmt.Errorf("SMTP configuration missing")
	}
	msg := []byte("To: " + toEmail + "\r\n" + "Subject: " + subject + "\r\n" + "Content-Type: text/html; charset=UTF-8\r\n" + "\r\n" + body)
	return sendMailWithTimeout(host, port, user, password, []string{toEmail}, msg)
}
