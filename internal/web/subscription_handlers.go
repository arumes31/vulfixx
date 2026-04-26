package web

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func SubscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.Method == "GET" {
		query := `SELECT id, keyword, min_severity, webhook_url, enable_email, enable_webhook FROM user_subscriptions WHERE user_id = $1`
		rows, err := db.Pool.Query(context.Background(), query, userID)
		if err != nil {
			log.Printf("Error fetching subscriptions: %v", err)
			RenderTemplate(w, r, "subscriptions.html", map[string]interface{}{"Error": "Error fetching subscriptions"})
			return
		}
		defer rows.Close()
		var subs []models.UserSubscription
		for rows.Next() {
			var s models.UserSubscription
			if err := rows.Scan(&s.ID, &s.Keyword, &s.MinSeverity, &s.WebhookURL, &s.EnableEmail, &s.EnableWebhook); err != nil {
				log.Printf("Error scanning subscription: %v", err)
				continue
			}
			subs = append(subs, s)
		}
		RenderTemplate(w, r, "subscriptions.html", map[string]interface{}{"Subscriptions": subs})
		return
	}
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			SendResponse(w, r, false, "", "", "Error parsing form")
			return
		}
		keyword := r.FormValue("keyword")
		minSeverityStr := r.FormValue("min_severity")
		webhookUrl := r.FormValue("webhook_url")
		minSeverity, _ := strconv.ParseFloat(minSeverityStr, 64)
		enableEmail := r.FormValue("enable_email") == "on" || r.FormValue("enable_email") == "true"
		enableWebhook := r.FormValue("enable_webhook") == "on" || r.FormValue("enable_webhook") == "true"

		_, err := db.Pool.Exec(context.Background(), `
			INSERT INTO user_subscriptions (user_id, keyword, min_severity, webhook_url, enable_email, enable_webhook)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, userID, keyword, minSeverity, webhookUrl, enableEmail, enableWebhook)
		if err != nil {
			SendResponse(w, r, false, "", "", "Error saving subscription")
			return
		}
		LogActivity(r.Context(), userID, "subscription_added", "Added keyword: "+keyword, r.RemoteAddr, r.UserAgent())
		SendResponse(w, r, true, "Telemetry monitor initialized", "/subscriptions", "")
	}
}

func DeleteSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}
	userID, ok := GetUserID(r)
	if !ok {
		SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}
	subIDStr := r.FormValue("id")
	subID, err := strconv.Atoi(subIDStr)
	if err != nil {
		SendResponse(w, r, false, "", "", "Invalid subscription ID")
		return
	}

	if _, err = db.Pool.Exec(context.Background(), "DELETE FROM user_subscriptions WHERE id = $1 AND user_id = $2", subID, userID); err != nil {
		SendResponse(w, r, false, "", "", "Error deleting subscription")
		return
	}
	LogActivity(r.Context(), userID, "subscription_deleted", "Deleted subscription ID: "+subIDStr, r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Telemetry pipeline removed", "/subscriptions", "")
}

func RSSFeedHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	minSeverityStr := r.URL.Query().Get("min_cvss")
	keyword := r.URL.Query().Get("q")

	if token == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	var userID int
	err := db.Pool.QueryRow(context.Background(), "SELECT id FROM users WHERE rss_feed_token = $1", token).Scan(&userID)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	minSeverity := 0.0
	if minSeverityStr != "" {
		minSeverity, _ = strconv.ParseFloat(minSeverityStr, 64)
	}

	query := `
		SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		WHERE (c.cvss_score >= us.min_severity OR c.cvss_score >= $2)
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%' OR $3 = '' OR c.description ILIKE '%' || $3 || '%')
		ORDER BY c.published_date DESC LIMIT 50
	`
	rows, err := db.Pool.Query(context.Background(), query, userID, minSeverity, keyword)
	if err != nil {
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/rss+xml")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
  <title>CVE Tracker Feed</title>
  <link>http://localhost:8080</link>
  <description>Latest CVEs matching your subscriptions</description>
`)

	for rows.Next() {
		var cve struct {
			CVEID       string
			Description string
			CVSSScore   float64
			PublishedAt time.Time
		}
		if err := rows.Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.PublishedAt); err != nil {
			continue
		}
		_, _ = fmt.Fprintf(w, `
  <item>
    <title>%s (CVSS: %.1f)</title>
    <link>https://nvd.nist.gov/vuln/detail/%s</link>
    <description>%s</description>
    <pubDate>%s</pubDate>
    <guid>%s</guid>
  </item>`, cve.CVEID, cve.CVSSScore, cve.CVEID, template.HTMLEscapeString(cve.Description), cve.PublishedAt.Format(time.RFC1123Z), cve.CVEID)
	}

	_, _ = fmt.Fprintf(w, `
</channel>
</rss>`)
}

func HandleAlertAction(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	action := r.URL.Query().Get("action")

	if token == "" || action == "" {
		http.Error(w, "Invalid action request", http.StatusBadRequest)
		return
	}

	dataBlob, err := db.RedisClient.Get(r.Context(), "alert_action:"+token).Result()
	if err != nil {
		http.Error(w, "This action link has expired or is invalid.", http.StatusGone)
		return
	}

	var data struct {
		UserID  int    `json:"user_id"`
		CVEID   int    `json:"cve_id"`
		Keyword string `json:"keyword"`
	}
	if err := json.Unmarshal([]byte(dataBlob), &data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if r.Method == "GET" {
		RenderTemplate(w, r, "confirm_action.html", map[string]interface{}{
			"Action":  action,
			"Keyword": data.Keyword,
			"CVEID":   data.CVEID,
		})
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	defer db.RedisClient.Del(ctx, "alert_action:"+token)

	switch action {
	case "acknowledge":
		_, err = db.Pool.Exec(ctx, `
			INSERT INTO user_cve_status (user_id, cve_id, status)
			VALUES ($1, $2, 'in_progress')
			ON CONFLICT (user_id, cve_id) DO UPDATE SET status = 'in_progress', updated_at = CURRENT_TIMESTAMP
		`, data.UserID, data.CVEID)
		if err != nil {
			http.Error(w, "Failed to acknowledge alert", http.StatusInternalServerError)
			return
		}
		LogActivity(ctx, data.UserID, "remediation", fmt.Sprintf("Acknowledged CVE ID %d via email", data.CVEID), r.RemoteAddr, r.UserAgent())
		RenderTemplate(w, r, "message.html", map[string]interface{}{
			"Title":   "Alert Acknowledged",
			"Message": "Vulnerability has been marked as 'In Progress'. View it in your dashboard for further analysis.",
		})

	case "mute":
		if strings.TrimSpace(data.Keyword) == "" {
			http.Error(w, "Invalid keyword for muting", http.StatusBadRequest)
			return
		}
		_, err = db.Pool.Exec(ctx, "DELETE FROM user_subscriptions WHERE user_id = $1 AND keyword = $2", data.UserID, data.Keyword)
		if err != nil {
			http.Error(w, "Failed to mute keyword", http.StatusInternalServerError)
			return
		}
		LogActivity(ctx, data.UserID, "alert_action", fmt.Sprintf("Muted keyword '%s' via email", data.Keyword), r.RemoteAddr, r.UserAgent())
		RenderTemplate(w, r, "message.html", map[string]interface{}{
			"Title":   "Keyword Muted",
			"Message": fmt.Sprintf("You will no longer receive alerts for the keyword '%s'.", data.Keyword),
		})

	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
	}
}
