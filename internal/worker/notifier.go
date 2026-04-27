package worker

import (
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
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

func sendAlert(sub models.UserSubscription, cve *models.CVE, email, assetName string) bool {
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
			payload, err := json.Marshal(payloadMap)
			if err != nil {
				log.Printf("Error marshaling webhook payload: %v", err)
				return
			}

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
			if err := db.RedisClient.Set(context.Background(), "alert_action:"+actionToken, actionData, 24*time.Hour).Err(); err != nil {
				log.Printf("Error storing action token in Redis: %v", err)
				return
			}

			baseURL := os.Getenv("BASE_URL")
			if baseURL == "" { baseURL = "http://localhost:8080" }
			if u, err := url.Parse(baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				log.Printf("Worker: Invalid BASE_URL %q, defaulting to localhost", baseURL)
				baseURL = "http://localhost:8080"
			}

			buttonsHTML := fmt.Sprintf(`
				<div style="margin-top: 30px; display: table; width: 100%%; border-collapse: separate; border-spacing: 10px 0;">
					<div style="display: table-cell; width: 50%%;">
						<a href="%s/alert-action?token=%s&action=acknowledge" style="display: block; background: #00daf3; color: #101418; text-align: center; padding: 12px 0; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 13px;">ACKNOWLEDGE</a>
					</div>
					<div style="display: table-cell; width: 50%%;">
						<a href="%s/alert-action?token=%s&action=mute" style="display: block; background: #1c2026; color: #dfe2eb; text-align: center; padding: 12px 0; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 13px; border: 1px solid #232931;">MUTE KEYWORD</a>
					</div>
				</div>
			`, baseURL, actionToken, baseURL, actionToken)
			body := fmt.Sprintf(`
				<div style="font-family: sans-serif; max-width: 600px; margin: auto; background: #101418; color: #dfe2eb; padding: 40px; border-radius: 12px; border: 1px solid #232931;">
					<h1 style="color: #ffffff; margin-top: 0;">%s</h1>
					%s %s
					<div style="margin: 20px 0; font-size: 14px; opacity: 0.8;">
						CVSS: <span style="color: %s; font-weight: bold;">%.1f (%s)</span> | EPSS: <span style="font-weight: bold;">%s</span>
					</div>
					<p style="line-height: 1.6; margin-bottom: 25px;">%s</p>
					%s
					<div style="margin-top: 25px; border-top: 1px solid #232931; pt: 20px;">
						<a href="%s/dashboard" style="display: block; text-align: center; color: #00daf3; text-decoration: none; font-size: 12px; font-weight: bold; padding-top: 20px;">OPEN DASHBOARD &rarr;</a>
					</div>
				</div>
			`, html.EscapeString(cve.CVEID), kevBadge, advisoryHTML, severityColor, cve.CVSSScore, severity, epssDisplay, html.EscapeString(cve.Description), buttonsHTML, baseURL)
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
