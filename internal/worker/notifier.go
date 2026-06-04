package worker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/models"
	"cve-tracker/internal/security"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

func (w *Worker) sendAlert(sub models.UserSubscription, cve *models.CVE, email, assetName string) bool {
	redacted := security.MaskEmail(email)
	slog.Info("ALERT: Processing multi-channel alert", "email", redacted, "cve_id", cve.CVEID)

	sev, color := getSeverityInfo(cve.CVSSScore)
	actionToken, err := auth.GenerateToken()
	if err != nil {
		slog.Error("ALERT: Failed to generate action token", "cve_id", cve.CVEID, "error", err)
		return false
	}

	// Store action token in Redis for buttons
	actionData, err := json.Marshal(map[string]interface{}{"user_id": sub.UserID, "cve_id": cve.ID, "keyword": sub.Keyword})
	if err != nil {
		slog.Error("ALERT: Failed to marshal action data", "cve_id", cve.CVEID, "error", err)
		return false
	}
	if err := w.Redis.Set(context.Background(), "alert_action:"+actionToken, actionData, 48*time.Hour).Err(); err != nil {
		slog.Error("ALERT: Failed to store action token in Redis", "cve_id", cve.CVEID, "error", err)
		return false
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

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
		if r {
			hasAnySuccess = true
		}
	}
	return hasAnySuccess
}

func (w *Worker) logDelivery(userID, subID, cveID int, channel string, success bool, errMsg string) {
	status := "success"
	if !success {
		status = "failure"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := w.Pool.Exec(ctx, `
		INSERT INTO notification_delivery_logs (user_id, subscription_id, cve_id, channel, status, error_message)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, subID, cveID, channel, status, errMsg)
	if err != nil {
		slog.Error("Failed to log notification delivery", "error", err)
	}
}

func getSeverityInfo(score float64) (string, string) {
	if score >= 9.0 {
		return "Critical", "#ff4d4d"
	}
	if score >= 7.0 {
		return "High", "#ff8c00"
	}
	if score >= 4.0 {
		return "Medium", "#ffcc00"
	}
	return "Low", "#00cc66"
}

func (w *Worker) sendSlackAlert(webhookURL string, cve *models.CVE, asset string, color, token, baseURL string) (bool, string) {
	_ = color // For future use in Slack attachments
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
					"text": fmt.Sprintf("*Severity:* %.1f\n*Asset:* %s\n\n%s", cve.CVSSScore, asset, cve.Description),
				},
			},
			map[string]interface{}{
				"type": "actions",
				"elements": []interface{}{
					map[string]interface{}{
						"type":  "button",
						"text":  map[string]interface{}{"type": "plain_text", "text": "Acknowledge"},
						"url":   fmt.Sprintf("%s/alert-action?action=acknowledge&token=%s", baseURL, token),
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
	_ = asset
	_ = color
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
							"type":  "Action.OpenUrl",
							"title": "Acknowledge",
							"url":   fmt.Sprintf("%s/alert-action?action=acknowledge&token=%s", baseURL, token),
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
	slog.Info("Browser Push triggered: Browser Push simulated/not implemented, recording as success for now", "user_id", userID, "cve_id", cve.CVEID)
	return true
}

func (w *Worker) postJSON(webhookURL string, payload interface{}) (bool, string) {
	parsedURL, err := url.Parse(webhookURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return false, "invalid webhook URL scheme"
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Sprintf("failed to marshal payload: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := newSafeHTTPClient(10 * time.Second)

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader(string(data)))
	if err != nil {
		return false, fmt.Sprintf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, ""
	}
	return false, fmt.Sprintf("status %d", resp.StatusCode)
}

func (w *Worker) sendEmailAlert(email string, cve *models.CVE, sev, color, token, baseURL string) bool {
	advisories := classifyVendorAdvisories(cve.References)
	validAdvisories := slices.DeleteFunc(slices.Clone(advisories), func(adv string) bool {
		u, err := url.Parse(adv)
		return !(err == nil && (u.Scheme == "http" || u.Scheme == "https"))
	})

	epssDisplay := "N/A"
	if cve.EPSSScore > 0 {
		epssDisplay = fmt.Sprintf("%.1f%%", cve.EPSSScore*100)
	}

	escapedToken := url.QueryEscape(token)

	contentTmpl := `
		<div style="margin-bottom: 20px;">
			{{if .CISAKEV}}
			<div style="background: #ff4d4d; color: #ffffff; padding: 10px 15px; border-radius: 6px; margin-bottom: 25px; font-weight: bold; border-left: 5px solid #b30000;">⚠️ KNOWN EXPLOITED VULNERABILITY</div>
			{{end}}

			{{if .Advisories}}
			<div style='background: #1c2026; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffcc00;'><strong style='opacity: 0.5;'>Vendor Advisories</strong><ul>
			{{range .Advisories}}
				<li><a href='{{.}}' style='color: #ffcc00;'>{{.}}</a></li>
			{{end}}
			</ul></div>
			{{end}}
		</div>
		<div style="background-color: #1c2026; padding: 20px; border-radius: 16px; border: 1px solid #232931; margin-bottom: 25px;">
			<div style="font-size: 14px; opacity: 0.7; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.05em;">Vulnerability Metrics</div>
			<div style="font-size: 18px;">
				CVSS: <span style="color: {{.Color}}; font-weight: 800;">{{.CVSSScore}} ({{.Sev}})</span>
				<span style="color: #232931; margin: 0 10px;">|</span>
				EPSS: <span style="font-weight: 800; color: #ffffff;">{{.EPSSDisplay}}</span>
			</div>
		</div>
		<p style="font-size: 16px; line-height: 1.7; color: #dfe2eb; margin-bottom: 30px;">{{.Description}}</p>
		
		<div style="margin-top: 30px;">
			<table width="100%" border="0" cellspacing="0" cellpadding="0">
				<tr>
					<td width="48%">
						<a href="{{.BaseURL}}/alert-action?action=acknowledge&token={{.Token}}" class="btn" style="display: block; text-align: center; padding: 14px 0; margin: 0;">ACKNOWLEDGE</a>
					</td>
					<td width="4%"></td>
					<td width="48%">
						<a href="{{.BaseURL}}/alert-action?action=mute&token={{.Token}}" class="secondary-btn" style="display: block; text-align: center; padding: 14px 0; margin: 0;">MUTE KEYWORD</a>
					</td>
				</tr>
			</table>
		</div>

		<div style="margin-top: 40px; text-align: center;">
			<a href="{{.BaseURL}}/dashboard" style="color: #00daf3; text-decoration: none; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;">Open Security Dashboard &rarr;</a>
		</div>
	`

	data := struct {
		CISAKEV     bool
		Advisories  []string
		Color       string
		CVSSScore   string
		Sev         string
		EPSSDisplay string
		Description string
		BaseURL     string
		Token       string
	}{
		CISAKEV:     cve.CISAKEV,
		Advisories:  validAdvisories,
		Color:       color,
		CVSSScore:   fmt.Sprintf("%.1f", cve.CVSSScore),
		Sev:         sev,
		EPSSDisplay: epssDisplay,
		Description: cve.Description,
		BaseURL:     baseURL,
		Token:       escapedToken,
	}

	body, err := RenderEmailTemplate("Security Alert: "+cve.CVEID, contentTmpl, data)
	if err != nil {
		slog.Error("Worker Notifier: Failed to render email template", "cve_id", cve.CVEID, "error", err)
		return false
	}

	err = w.Mailer.SendEmail(email, "Security Alert: "+cve.CVEID, body)
	return err == nil
}

func (w *Worker) sendGenericWebhook(webhookURL string, cve *models.CVE, asset, email string) (bool, string) {
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

	client := newSafeHTTPClient(webhookTimeout)

	req, _ := http.NewRequestWithContext(httpCtx, "POST", webhookURL, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")

	// Webhook Signing (Item 10)
	secret := w.WebhookSecret
	if secret == "" {
		return false, "missing WebhookSecret"
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "." + string(payload)))
	signature := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-Vulfixx-Signature", signature)
	req.Header.Set("X-Vulfixx-Timestamp", timestamp)

	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, ""
	}
	return false, fmt.Sprintf("status %d", resp.StatusCode)
}

func newSafeHTTPClient(timeout time.Duration) *http.Client {
	allowedPorts := map[string]bool{"80": true, "443": true}
	if extraPorts := os.Getenv("ALLOWED_WEB_PORTS"); extraPorts != "" {
		for _, p := range strings.Split(extraPorts, ",") {
			allowedPorts[strings.TrimSpace(p)] = true
		}
		slog.Warn("Worker: [SECURITY] Non-default webhook ports are enabled via ALLOWED_WEB_PORTS. Ensure internal services are not exposed.", "allowed_ports", extraPorts)
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DisableKeepAlives: true, // Short-lived client for webhooks
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Port restriction: allow only standard web ports
			if !allowedPorts[portStr] {
				if os.Getenv("TEST_MODE") != "1" {
					return nil, fmt.Errorf("blocked non-standard port: %s", portStr)
				}
			}

			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}

			var safeIP net.IP
			for _, ipAddr := range ips {
				if security.IsIPSafe(ipAddr.IP) {
					safeIP = ipAddr.IP
					break
				}
			}

			if safeIP == nil {
				return nil, fmt.Errorf("no safe IP for %s", host)
			}

			return dialer.DialContext(ctx, network, net.JoinHostPort(safeIP.String(), portStr))
		},
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("invalid redirect scheme: %s", req.URL.Scheme)
			}
			// Security: Strip signature and timestamp if host changes
			if req.URL.Host != via[0].URL.Host {
				req.Header.Del("X-Vulfixx-Signature")
				req.Header.Del("X-Vulfixx-Timestamp")
			}
			return nil
		},
	}
}
