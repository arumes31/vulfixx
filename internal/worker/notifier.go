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
	log.Printf("ALERT: Sending to %s for %s\n", email, cve.CVEID)
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
			`, html.EscapeString(cve.CVEID), kevBadge, advisoryHTML, severityColor, cve.CVSSScore, severity, epssDisplay, html.EscapeString(cve.Description), os.Getenv("BASE_URL"), os.Getenv("BASE_URL"))
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
