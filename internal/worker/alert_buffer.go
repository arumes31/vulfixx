package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/url"
	"os"
	"time"
)

var (
	bufferTimeHigh     = 1 * time.Minute
	bufferTimeStandard = 5 * time.Minute
)

func (w *Worker) bufferAlert(ctx context.Context, userID int, cve *models.CVE, sub models.UserSubscription, email, assetName string) bool {
	// Severity-Based Routing:
	// Critical (>= 9.0) gets immediate delivery.
	if cve.CVSSScore >= 9.0 {
		return w.sendAlert(sub, cve, email, assetName)
	}

	key := fmt.Sprintf("alert_buffer:%d", userID)
	data := map[string]interface{}{
		"id":         fmt.Sprintf("%d_%d", time.Now().UnixNano(), userID), // Unique ID for safe LRem
		"cve":        cve,
		"email":      email,
		"asset_name": assetName,
		"sub":        sub,
	}
	blob, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling alert buffer data: %v", err)
		return false
	}
	if err := w.Redis.RPush(ctx, key, blob).Err(); err != nil {
		log.Printf("Error pushing to alert buffer: %v", err)
		return false
	}

	processingKey := fmt.Sprintf("alert_processing:%d", userID)
	// Lock TTL = buffer time + processing buffer
	set, err := w.Redis.SetNX(ctx, processingKey, "true", bufferTimeStandard+10*time.Minute).Result()
	if err != nil {
		log.Printf("Error setting alert processing lock for key %s: %v", processingKey, err)
		// Rollback the pushed alert
		if rErr := w.Redis.LRem(ctx, key, 1, blob).Err(); rErr != nil {
			log.Printf("Error rolling back pushed alert for %s: %v", key, rErr)
		}
		return false
	}
	if set {
		bufferTime := bufferTimeStandard
		if cve.CVSSScore >= 7.0 {
			bufferTime = bufferTimeHigh
		}
		/* #nosec G118 */
		go func(bTime time.Duration, pKey string, uid int) {
			bgCtx := context.Background()
			defer func() {
				cleanupCtx, cancel := context.WithTimeout(bgCtx, 5*time.Second)
				defer cancel()
				w.Redis.Del(cleanupCtx, pKey)
			}()

			// Initial wait
			time.Sleep(bTime)

			for {
				w.processUserBuffer(bgCtx, uid)

				// Re-check buffer length
				bufferKey := fmt.Sprintf("alert_buffer:%d", uid)
				llen, err := w.Redis.LLen(bgCtx, bufferKey).Result()
				if err != nil || llen == 0 {
					break
				}
				// Small backoff before reprocessing
				time.Sleep(1 * time.Second)
			}
		}(bufferTime, processingKey, userID)
	}
	return true
}

func (w *Worker) processUserBuffer(ctx context.Context, userID int) {
	key := fmt.Sprintf("alert_buffer:%d", userID)
	// Atomic: Fetch all and delete
	pipe := w.Redis.TxPipeline()
	lrange := pipe.LRange(ctx, key, 0, -1)
	pipe.Del(ctx, key)
	_, err := pipe.Exec(ctx)
	if err != nil {
		log.Printf("Error processing alert buffer for user %d: %v", userID, err)
		return
	}
	blobs, err := lrange.Result()
	if err != nil {
		log.Printf("Error getting alert buffer result: %v", err)
		return
	}
	if len(blobs) == 0 {
		return
	}

	type alertData struct {
		CVE       models.CVE              `json:"cve"`
		Email     string                  `json:"email"`
		AssetName string                  `json:"asset_name"`
		Sub       models.UserSubscription `json:"sub"`
	}

	if len(blobs) == 1 {
		var data alertData
		if err := json.Unmarshal([]byte(blobs[0]), &data); err != nil {
			log.Printf("Error unmarshaling single buffered alert: %v", err)
			return
		}
		w.sendAlert(data.Sub, &data.CVE, data.Email, data.AssetName)
		return
	}

	uniqueEmails := make(map[string]bool)
	type AlertItem struct {
		CVEID     string
		Score     float64
		AssetName string
		Buzz      int
		HasOSINT  bool
		CVE       *models.CVE
	}
	var items []AlertItem
	for _, b := range blobs {
		var data alertData
		if err := json.Unmarshal([]byte(b), &data); err != nil {
			log.Printf("Error unmarshaling alert blob: %v", err)
			continue
		}
		if data.Email != "" {
			uniqueEmails[data.Email] = true
		}
		hasOSINT := false
		if hn, ok := data.CVE.OSINTData["hn"].([]interface{}); ok && len(hn) > 0 {
			hasOSINT = true
		} else if r, ok := data.CVE.OSINTData["reddit"].([]interface{}); ok && len(r) > 0 {
			hasOSINT = true
		}
		// Also invoke webhook for each item individually since it's a digest
		cveCopy := data.CVE
		w.sendAlert(data.Sub, &cveCopy, data.Email, data.AssetName)

		items = append(items, AlertItem{
			CVEID:     data.CVE.CVEID,
			Score:     data.CVE.CVSSScore,
			AssetName: data.AssetName,
			Buzz:      data.CVE.GitHubPoCCount,
			HasOSINT:  hasOSINT,
			CVE:       &cveCopy,
		})
	}
	rowsHTML := ""
	for _, item := range items {
		assetInfo := ""
		if item.AssetName != "" {
			assetInfo = fmt.Sprintf("<br><span style='font-size: 11px; opacity: 0.6;'>Asset: %s</span>", html.EscapeString(item.AssetName))
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
		`, html.EscapeString(item.CVEID), assetInfo, html.EscapeString(buzzBadge), item.Score)
	}
	baseURLStr := os.Getenv("BASE_URL")
	if baseURLStr == "" {
		baseURLStr = "http://localhost:8080"
	}
	parsedBase, err := url.Parse(baseURLStr)
	if err != nil || (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") {
		baseURLStr = "http://localhost:8080"
	} else {
		baseURLStr = parsedBase.String()
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
	`, len(items), rowsHTML, baseURLStr)

	if len(uniqueEmails) == 0 {
		log.Printf("Error: No recipient email found for user %d digest", userID)
		return
	}

	for email := range uniqueEmails {
		if err := w.Mailer.SendEmail(email, "Threat Brief: Multiple Vulnerabilities Detected", body); err != nil {
			log.Printf("Failed to send threat brief to %s: %v", maskEmail(email), err)
		}
	}
}
