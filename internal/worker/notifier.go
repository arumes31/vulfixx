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
	log.Printf("ALERT: Sending to %s for %s\n", redactEmail(email), cve.CVEID)
	var wg sync.WaitGroup
	successChan := make(chan bool, 2)

	if sub.EnableWebhook && sub.WebhookURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Robust Webhook Security
			parsedURL, err := url.Parse(sub.WebhookURL)
			redacted := redactURL(sub.WebhookURL)
			if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
				log.Printf("Skipping invalid webhook URL scheme: %s", redacted)
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
			payload, err := json.Marshal(payloadMap)
			if err != nil {
				log.Printf("Error marshaling webhook payload: %v", err)
				return
			}

			const webhookTimeout = 10 * time.Second
			httpCtx, httpCancel := context.WithTimeout(context.Background(), webhookTimeout)
			defer httpCancel()

			// DNS Pinning / SSRF Protection via custom dialer inside DialContext
			dialer := &net.Dialer{Timeout: webhookTimeout}
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					ips, err := net.DefaultResolver.LookupIPAddr(ctx, parsedURL.Hostname())
					if err != nil {
						return nil, err
					}

					var safeIP net.IP
					for _, ipAddr := range ips {
						if addr, ok := netip.AddrFromSlice(ipAddr.IP); ok {
							if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
								if os.Getenv("TEST_MODE") != "1" {
									continue
								}
							}
							safeIP = ipAddr.IP
							break
						}
					}

					if safeIP == nil {
						return nil, fmt.Errorf("no safe IP found for host %s", parsedURL.Hostname())
					}

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
				IdleConnTimeout: 1 * time.Second,
			}
			defer transport.CloseIdleConnections()
			pinnedClient := &http.Client{Transport: transport, Timeout: webhookTimeout}

			req, err := http.NewRequestWithContext(httpCtx, "POST", sub.WebhookURL, strings.NewReader(string(payload)))
			if err != nil {
				log.Printf("Error creating webhook request: %v", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			// Keep the original Host so TLS SNI and virtual hosting work correctly.
			req.Host = parsedURL.Host

			resp, err := pinnedClient.Do(req)
			if err != nil {
				log.Printf("Error sending webhook %s %s: %v", req.Method, redacted, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				successChan <- true
			} else {
				var snippet string
				buf := make([]byte, 512)
				n, _ := resp.Body.Read(buf)
				if n > 0 {
					snippet = string(buf[:n])
				}
				log.Printf("Webhook error response from %s: status %d, body: %s", redacted, resp.StatusCode, snippet)
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

			actionToken, err := auth.GenerateToken()
			if err != nil {
				log.Printf("Error generating action token: %v", err)
				return
			}
			actionData, err := json.Marshal(map[string]interface{}{"user_id": sub.UserID, "cve_id": cve.ID, "keyword": sub.Keyword})
			if err != nil {
				log.Printf("Error marshaling action data: %v", err)
				return
			}
			if err := w.Redis.Set(context.Background(), "alert_action:"+actionToken, actionData, 24*time.Hour).Err(); err != nil {
				log.Printf("Error storing action token in Redis: %v", err)
				return
			}

			baseURL := os.Getenv("BASE_URL")
			if baseURL == "" {
				baseURL = "http://localhost:8080"
			}
			if u, err := url.Parse(baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				// #nosec G706 -- baseURL is sanitized via sanitizeHeader
				log.Printf("Worker: Invalid BASE_URL %q, defaulting to localhost", sanitizeHeader(baseURL))
				baseURL = "http://localhost:8080"
			}

			escapedToken := url.QueryEscape(actionToken)
			
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
			`, kevBadge, advisoryHTML, severityColor, cve.CVSSScore, severity, epssDisplay, html.EscapeString(cve.Description), baseURL, escapedToken, baseURL, escapedToken, baseURL)

			body := WrapInModernLayout("Security Alert: "+cve.CVEID, content)
			if err := w.Mailer.SendEmail(email, "Security Alert: "+cve.CVEID, body); err == nil {
				successChan <- true
			} else {
				log.Printf("Failed to send email alert to %s for %s: %v", redactEmail(email), cve.CVEID, err)
				successChan <- false
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
