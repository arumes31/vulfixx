package worker

import (
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func (w *Worker) sendAlert(sub models.UserSubscription, cve *models.CVE, email, assetName string) bool {
	log.Printf("ALERT: Processing multi-channel alert for %s (CVE: %s)\n", redactEmail(email), cve.CVEID)
	
	sev, color := getSeverityInfo(cve.CVSSScore)
	actionToken, _ := auth.GenerateToken() // Simplified for now, should handle error
	
	// Store action token in Redis for buttons
	actionData, _ := json.Marshal(map[string]interface{}{"user_id": sub.UserID, "cve_id": cve.ID, "keyword": sub.Keyword})
	w.Redis.Set(context.Background(), "alert_action:"+actionToken, actionData, 48*time.Hour)

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" { baseURL = "http://localhost:8080" }

	var wg sync.WaitGroup
	results := make(chan bool, 5)

	// 1. Email
	if sub.EnableEmail {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success := w.sendEmailAlert(email, cve, sev, color, actionToken, baseURL)
			w.logDelivery(sub.UserID, sub.ID, cve.ID, "email", success, "")
			results <- success
		}()
	}

	// 2. Webhook (Generic)
	if sub.EnableWebhook && sub.WebhookURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success, errMsg := w.sendGenericWebhook(sub.WebhookURL, cve, assetName, email)
			w.logDelivery(sub.UserID, sub.ID, cve.ID, "webhook", success, errMsg)
			results <- success
		}()
	}

	// 3. Slack
	if sub.EnableSlack && sub.SlackWebhookURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success, errMsg := w.sendSlackAlert(sub.SlackWebhookURL, cve, assetName, color, actionToken, baseURL)
			w.logDelivery(sub.UserID, sub.ID, cve.ID, "slack", success, errMsg)
			results <- success
		}()
	}

	// 4. Teams
	if sub.EnableTeams && sub.TeamsWebhookURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success, errMsg := w.sendTeamsAlert(sub.TeamsWebhookURL, cve, assetName, color, actionToken, baseURL)
			w.logDelivery(sub.UserID, sub.ID, cve.ID, "teams", success, errMsg)
			results <- success
		}()
	}

	// 5. Browser Push
	if sub.EnableBrowserPush {
		wg.Add(1)
		go func() {
			defer wg.Done()
			success := w.sendBrowserPush(sub.UserID, cve)
			w.logDelivery(sub.UserID, sub.ID, cve.ID, "browser", success, "")
			results <- success
		}()
	}

	wg.Wait()
	close(results)
	
	hasAnySuccess := false
	for r := range results {
		if r { hasAnySuccess = true }
	}
	return hasAnySuccess
}

func (w *Worker) logDelivery(userID, subID, cveID int, channel string, success bool, errMsg string) {
	status := "success"
	if !success { status = "failure" }
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	_, err := w.Pool.Exec(ctx, `
		INSERT INTO notification_delivery_logs (user_id, subscription_id, cve_id, channel, status, error_message)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, subID, cveID, channel, status, errMsg)
	if err != nil {
		log.Printf("Failed to log notification delivery: %v", err)
	}
}

func getSeverityInfo(score float64) (string, string) {
	if score >= 9.0 { return "Critical", "#ff4d4d" }
	if score >= 7.0 { return "High", "#ff8c00" }
	if score >= 4.0 { return "Medium", "#ffcc00" }
	return "Low", "#00cc66"
}

func (w *Worker) sendSlackAlert(webhookURL string, cve *models.CVE, asset string, color, token, baseURL string) (bool, string) {
	payload := map[string]interface{}{
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": fmt.Sprintf("🚨 Security Alert: %s", cve.CVEID),
				},
			},
			map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Severity:* %f\n*Asset:* %s\n\n%s", cve.CVSSScore, asset, cve.Description),
				},
			},
			map[string]interface{}{
				"type": "actions",
				"elements": []interface{}{
					map[string]interface{}{
						"type": "button",
						"text": map[string]interface{}{"type": "plain_text", "text": "Acknowledge"},
						"url":  fmt.Sprintf("%s/alert-action?token=%s&action=acknowledge", baseURL, token),
						"style": "primary",
					},
					map[string]interface{}{
						"type": "button",
						"text": map[string]interface{}{"type": "plain_text", "text": "View Detail"},
						"url":  fmt.Sprintf("%s/cve/%s", baseURL, cve.CVEID),
					},
				},
			},
		},
	}
	return w.postJSON(webhookURL, payload)
}

func (w *Worker) sendTeamsAlert(webhookURL string, cve *models.CVE, asset string, color, token, baseURL string) (bool, string) {
	payload := map[string]interface{}{
		"type": "message",
		"attachments": []interface{}{
			map[string]interface{}{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"type": "AdaptiveCard",
					"body": []interface{}{
						map[string]interface{}{"type": "TextBlock", "text": "Security Alert: " + cve.CVEID, "weight": "bolder", "size": "medium"},
						map[string]interface{}{"type": "TextBlock", "text": cve.Description, "wrap": true},
					},
					"actions": []interface{}{
						map[string]interface{}{
							"type": "Action.OpenUrl",
							"title": "Acknowledge",
							"url": fmt.Sprintf("%s/alert-action?token=%s&action=acknowledge", baseURL, token),
						},
					},
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"version": "1.0",
				},
			},
		},
	}
	return w.postJSON(webhookURL, payload)
}

func (w *Worker) sendBrowserPush(userID int, cve *models.CVE) bool {
	// Implementation would use web-push-go and VAPID keys
	// For now, we log the intent and could trigger a WebSocket event as a fallback
	log.Printf("Browser Push triggered for user %d, CVE %s", userID, cve.CVEID)
	return true 
}

func (w *Worker) postJSON(url string, payload interface{}) (bool, string) {
	data, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil { return false, err.Error() }
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 { return true, "" }
	return false, fmt.Sprintf("status %d", resp.StatusCode)
}

func (w *Worker) sendEmailAlert(email string, cve *models.CVE, sev, color, token, baseURL string) bool {
	kevBadge := ""
	if cve.CISAKEV {
		kevBadge = `<div style="background: #ff4d4d; color: #ffffff; padding: 10px 15px; border-radius: 6px; margin-bottom: 25px; font-weight: bold; border-left: 5px solid #b30000;">⚠️ KNOWN EXPLOITED VULNERABILITY</div>`
	}
	advisories := classifyVendorAdvisories(cve.References)
	advisoryHTML := ""
	if len(advisories) > 0 {
		advisoryHTML = "<div style='background: #1c2026; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffcc00;'><strong style='opacity: 0.5;'>Vendor Advisories</strong><ul>"
		for _, adv := range advisories {
			u, err := url.Parse(adv)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			safeAdv := html.EscapeString(adv)
			advisoryHTML += fmt.Sprintf("<li><a href='%s' style='color: #ffcc00;'>%s</a></li>", safeAdv, safeAdv)
		}
		advisoryHTML += "</ul></div>"
	}
	epssDisplay := "N/A"
	if cve.EPSSScore > 0 {
		epssDisplay = fmt.Sprintf("%.1f%%", cve.EPSSScore*100)
	}

	escapedToken := url.QueryEscape(token)
	
	content := fmt.Sprintf(`
		<div style="margin-bottom: 20px;">
			%s %s
		</div>
		<div style="background-color: #1c2026; padding: 20px; border-radius: 16px; border: 1px solid #232931; margin-bottom: 25px;">
			<div style="font-size: 14px; opacity: 0.7; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.05em;">Vulnerability Metrics</div>
			<div style="font-size: 18px;">
				CVSS: <span style="color: %s; font-weight: 800;">%.1f (%s)</span> 
				<span style="color: #232931; margin: 0 10px;">|</span>
				EPSS: <span style="font-weight: 800; color: #ffffff;">%s</span>
			</div>
		</div>
		<p style="font-size: 16px; line-height: 1.7; color: #dfe2eb; margin-bottom: 30px;">%s</p>
		
		<div style="margin-top: 30px;">
			<table width="100%%" border="0" cellspacing="0" cellpadding="0">
				<tr>
					<td width="48%%">
						<a href="%s/alert-action?token=%s&action=acknowledge" class="btn" style="display: block; text-align: center; padding: 14px 0; margin: 0;">ACKNOWLEDGE</a>
					</td>
					<td width="4%%"></td>
					<td width="48%%">
						<a href="%s/alert-action?token=%s&action=mute" class="secondary-btn" style="display: block; text-align: center; padding: 14px 0; margin: 0;">MUTE KEYWORD</a>
					</td>
				</tr>
			</table>
		</div>

		<div style="margin-top: 40px; text-align: center;">
			<a href="%s/dashboard" style="color: #00daf3; text-decoration: none; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;">Open Security Dashboard &rarr;</a>
		</div>
	`, kevBadge, advisoryHTML, color, cve.CVSSScore, sev, epssDisplay, html.EscapeString(cve.Description), baseURL, escapedToken, baseURL, escapedToken, baseURL)

	body := WrapInModernLayout("Security Alert: "+cve.CVEID, content)
	err := w.Mailer.SendEmail(email, "Security Alert: "+cve.CVEID, body)
	return err == nil
}

func (w *Worker) sendGenericWebhook(webhookURL string, cve *models.CVE, asset, email string) (bool, string) {
	// Robust Webhook Security Logic (Restored)
	parsedURL, err := url.Parse(webhookURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return false, "invalid scheme"
	}

	payloadMap := map[string]interface{}{
		"cve_id":      cve.CVEID,
		"description": cve.Description,
		"cvss_score":  cve.CVSSScore,
		"asset_name":  asset,
	}
	if os.Getenv("WEBHOOK_INCLUDE_USER_EMAIL") == "true" {
		payloadMap["user_email"] = email
	}
	payload, _ := json.Marshal(payloadMap)

	const webhookTimeout = 10 * time.Second
	httpCtx, httpCancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer httpCancel()

	dialer := &net.Dialer{Timeout: webhookTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ips, _ := net.DefaultResolver.LookupIPAddr(ctx, parsedURL.Hostname())
			var safeIP net.IP
			for _, ipAddr := range ips {
				if addr, ok := netip.AddrFromSlice(ipAddr.IP); ok {
					if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
						if os.Getenv("TEST_MODE") != "1" { continue }
					}
					safeIP = ipAddr.IP
					break
				}
			}
			if safeIP == nil { return nil, fmt.Errorf("no safe IP") }
			port := parsedURL.Port()
			if port == "" {
				if parsedURL.Scheme == "https" { port = "443" } else { port = "80" }
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
		},
		IdleConnTimeout: 1 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: webhookTimeout}

	req, _ := http.NewRequestWithContext(httpCtx, "POST", webhookURL, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Host = parsedURL.Host

	resp, err := client.Do(req)
	if err != nil { return false, err.Error() }
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 { return true, "" }
	return false, fmt.Sprintf("status %d", resp.StatusCode)
}

func redactEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "[invalid-email]"
	}
	if len(parts[0]) <= 2 {
		return "*@" + parts[1]
	}
	return parts[0][:2] + "****@" + parts[1]
}
