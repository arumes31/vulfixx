package worker

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func processAlerts(ctx context.Context) {
	for {
		result, err := db.RedisClient.BRPop(ctx, 0, "cve_alerts_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
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

func evaluateSubscriptions(ctx context.Context, cve *models.CVE) {
	rows, err := db.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.keyword, s.min_severity, s.webhook_url, s.enable_email, s.enable_webhook, s.filter_logic, u.email
		FROM user_subscriptions s
		JOIN users u ON s.user_id = u.id
		WHERE u.is_email_verified = TRUE
		  AND s.min_severity <= $1
		  AND (s.keyword = '' OR $2 ILIKE '%' || s.keyword || '%')
	`, cve.CVSSScore, cve.Description)
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
		  AND $1 ILIKE '%' || ak.keyword || '%'
	`, cve.Description)
	if err != nil {
		log.Println("Error fetching asset keywords:", err)
		return
	}
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
			val, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return false
			}
			if cve.EPSSScore <= val {
				return false
			}
		} else {
			return false
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
			val, err := strconv.Atoi(valStr)
			if err != nil {
				return false
			}
			if cve.GitHubPoCCount <= val {
				return false
			}
		} else {
			return false
		}
	}

	// Regex Filter support
	if strings.Contains(logic, "regex:") {
		parts := strings.Split(logic, "regex:")
		if len(parts) > 1 {
			pattern := strings.TrimSpace(strings.Split(parts[1], " ")[0])
			re, err := regexp.Compile(pattern)
			if err == nil {
				if !re.MatchString(cve.Description) {
					return false
				}
			}
		}
	}

	return true
}

func notifyIfNew(ctx context.Context, userID, cveID int, sub models.UserSubscription, email, assetName string) bool {
	res, err := db.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING", userID, cveID)
	if err != nil {
		log.Printf("Failed to record alert history: %v", err)
		return false
	}
	if res.RowsAffected() == 0 {
		return false
	}
	var cve models.CVE
	err = db.Pool.QueryRow(ctx, `
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
