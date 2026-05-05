package web

import (
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/csrf"
)

// escapeLikePattern escapes backslash, percent, and underscore so the value can
// be safely embedded in a PostgreSQL ILIKE pattern using ESCAPE '\'.
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func (a *App) SubscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.Method == "GET" {
		query := `
			SELECT us.id, us.keyword, us.min_severity, us.webhook_url,
			       COALESCE(us.slack_webhook_url, '') as slack_webhook_url,
			       COALESCE(us.teams_webhook_url, '') as teams_webhook_url,
			       us.enable_email, us.enable_webhook,
			       COALESCE(us.enable_slack, false) as enable_slack,
			       COALESCE(us.enable_teams, false) as enable_teams,
			       COALESCE(us.enable_browser_push, false) as enable_browser_push,
			       COALESCE(us.aggregation_mode, 'instant') as aggregation_mode,
			       us.team_id
			FROM user_subscriptions us
			WHERE us.user_id = $1 OR us.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1)
		`
		rows, err := a.Pool.Query(r.Context(), query, userID)
		if err != nil {
			log.Printf("Error fetching subscriptions: %v", err)
			a.RenderTemplate(w, r, "subscriptions.html", map[string]interface{}{"Error": "Error fetching subscriptions"})
			return
		}
		defer rows.Close()
		var subs []models.UserSubscription
		for rows.Next() {
			var s models.UserSubscription
			if err := rows.Scan(&s.ID, &s.Keyword, &s.MinSeverity, &s.WebhookURL,
				&s.SlackWebhookURL, &s.TeamsWebhookURL,
				&s.EnableEmail, &s.EnableWebhook,
				&s.EnableSlack, &s.EnableTeams, &s.EnableBrowserPush,
				&s.AggregationMode, &s.TeamID); err != nil {
				log.Printf("Error scanning subscription: %v", err)
				continue
			}
			subs = append(subs, s)
		}
		if err := rows.Err(); err != nil {
			log.Printf("Error iterating subscriptions: %v", err)
		}
		a.RenderTemplate(w, r, "subscriptions.html", map[string]interface{}{
			"Subscriptions": subs,
			"csrfToken":     csrf.Token(r),
		})
		return
	}
	if r.Method == "POST" {
		var jsonData struct {
			Keyword         string  `json:"keyword"`
			MinSeverity     float64 `json:"min_severity"`
			WebhookURL      string  `json:"webhook_url"`
			SlackWebhookURL string  `json:"slack_webhook_url"`
			TeamsWebhookURL string  `json:"teams_webhook_url"`
			EnableEmail     bool    `json:"enable_email"`
			EnableWebhook   bool    `json:"enable_webhook"`
			EnableSlack     bool    `json:"enable_slack"`
			EnableTeams     bool    `json:"enable_teams"`
			EnableBrowserPush bool  `json:"enable_browser_push"`
			AggregationMode string  `json:"aggregation_mode"`
		}

		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&jsonData); err != nil {
				a.SendResponse(w, r, false, "", "", "Error decoding JSON")
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				a.SendResponse(w, r, false, "", "", "Error parsing form")
				return
			}
			jsonData.Keyword = strings.TrimSpace(r.FormValue("keyword"))
			jsonData.MinSeverity, _ = strconv.ParseFloat(r.FormValue("min_severity"), 64)
			jsonData.WebhookURL = strings.TrimSpace(r.FormValue("webhook_url"))
			jsonData.SlackWebhookURL = strings.TrimSpace(r.FormValue("slack_webhook_url"))
			jsonData.TeamsWebhookURL = strings.TrimSpace(r.FormValue("teams_webhook_url"))
			jsonData.EnableEmail = r.FormValue("enable_email") == "on" || r.FormValue("enable_email") == "true"
			jsonData.EnableWebhook = r.FormValue("enable_webhook") == "on" || r.FormValue("enable_webhook") == "true"
			jsonData.EnableSlack = r.FormValue("enable_slack") == "on" || r.FormValue("enable_slack") == "true"
			jsonData.EnableTeams = r.FormValue("enable_teams") == "on" || r.FormValue("enable_teams") == "true"
			jsonData.EnableBrowserPush = r.FormValue("enable_browser_push") == "on" || r.FormValue("enable_browser_push") == "true"
			jsonData.AggregationMode = strings.TrimSpace(r.FormValue("aggregation_mode"))
		}

		if jsonData.Keyword == "" {
			a.SendResponse(w, r, false, "", "", "Keyword is required")
			return
		}
		if len(jsonData.Keyword) > 100 {
			a.SendResponse(w, r, false, "", "", "Target infrastructure keyword too long (max 100 characters)")
			return
		}

		if jsonData.MinSeverity < 0 || jsonData.MinSeverity > 10 {
			a.SendResponse(w, r, false, "", "", "Invalid severity score (must be 0-10)")
			return
		}

		if jsonData.EnableWebhook {
			if jsonData.WebhookURL == "" {
				a.SendResponse(w, r, false, "", "", "A webhook URL is required")
				return
			}
			parsed, err := url.ParseRequestURI(jsonData.WebhookURL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				a.SendResponse(w, r, false, "", "", "A valid HTTP/HTTPS webhook URL is required")
				return
			}

			// SSRF protection: block internal/loopback IPs
			host := parsed.Hostname()
			ips, err := net.LookupIP(host)
			if err != nil {
				a.SendResponse(w, r, false, "", "", "Invalid webhook host")
				return
			}
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
					a.SendResponse(w, r, false, "", "", "Internal or restricted webhook URLs are not allowed")
					return
				}
			}

			jsonData.WebhookURL = parsed.String()

			if len(jsonData.WebhookURL) > 2048 {
				a.SendResponse(w, r, false, "", "", "Webhook URL is too long")
				return
			}
		}

		// Default aggregation_mode if not set
		if jsonData.AggregationMode == "" {
			jsonData.AggregationMode = "instant"
		}
		if jsonData.AggregationMode != "instant" && jsonData.AggregationMode != "hourly" && jsonData.AggregationMode != "daily" {
			a.SendResponse(w, r, false, "", "", "Invalid aggregation mode")
			return
		}

		ctx := r.Context()
		tx, err := a.Pool.Begin(ctx)
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		// Enforce limit atomically
		var count int
		var maxSubs int
		// Lock the user row to prevent concurrent subscription additions and fetch their quota
		err = tx.QueryRow(ctx, "SELECT max_subscriptions FROM users WHERE id = $1 FOR UPDATE", userID).Scan(&maxSubs)
		if err != nil {
			log.Printf("Error fetching user quota: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1", userID).Scan(&count)
		if err != nil {
			log.Printf("Error counting subscriptions: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		if count >= maxSubs {
			a.SendResponse(w, r, false, "", "", fmt.Sprintf("Maximum of %d subscriptions allowed for your account level", maxSubs))
			return
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO user_subscriptions (user_id, keyword, min_severity, webhook_url, slack_webhook_url, teams_webhook_url,
			    enable_email, enable_webhook, enable_slack, enable_teams, enable_browser_push, aggregation_mode)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`, userID, jsonData.Keyword, jsonData.MinSeverity, jsonData.WebhookURL,
			jsonData.SlackWebhookURL, jsonData.TeamsWebhookURL,
			jsonData.EnableEmail, jsonData.EnableWebhook,
			jsonData.EnableSlack, jsonData.EnableTeams, jsonData.EnableBrowserPush,
			jsonData.AggregationMode)
		if err != nil {
			log.Printf("Error saving subscription: %v", err)
			a.SendResponse(w, r, false, "", "", "Error saving subscription")
			return
		}

		if err = tx.Commit(ctx); err != nil {
			log.Printf("Error committing transaction: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
		a.LogActivity(ctx, userID, "subscription_added", "Added keyword: "+jsonData.Keyword, a.GetClientIP(r), r.UserAgent())
		a.SendResponse(w, r, true, "Telemetry monitor initialized", "/subscriptions", "")
		return
	}
}

func (a *App) DeleteSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}
	subIDStr := r.FormValue("id")
	subID, err := strconv.Atoi(subIDStr)
	if err != nil {
		a.SendResponse(w, r, false, "", "", "Invalid subscription ID")
		return
	}

	if _, err = a.Pool.Exec(r.Context(), "DELETE FROM user_subscriptions WHERE id = $1 AND user_id = $2", subID, userID); err != nil {
		a.SendResponse(w, r, false, "", "", "Error deleting subscription")
		return
	}
	a.LogActivity(r.Context(), userID, "subscription_deleted", "Deleted subscription ID: "+subIDStr, a.GetClientIP(r), r.UserAgent())
	a.SendResponse(w, r, true, "Telemetry pipeline removed", "/subscriptions", "")
}

func (a *App) UpdateSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	var jsonData struct {
		ID              int     `json:"id"`
		Keyword         string  `json:"keyword"`
		MinSeverity     float64 `json:"min_severity"`
		WebhookURL      string  `json:"webhook_url"`
		SlackWebhookURL string  `json:"slack_webhook_url"`
		TeamsWebhookURL string  `json:"teams_webhook_url"`
		EnableEmail     bool    `json:"enable_email"`
		EnableWebhook   bool    `json:"enable_webhook"`
		EnableSlack     bool    `json:"enable_slack"`
		EnableTeams     bool    `json:"enable_teams"`
		EnableBrowserPush bool  `json:"enable_browser_push"`
		AggregationMode string  `json:"aggregation_mode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&jsonData); err != nil {
		a.SendResponse(w, r, false, "", "", "Error decoding JSON")
		return
	}

	if jsonData.ID == 0 {
		a.SendResponse(w, r, false, "", "", "Subscription ID is required")
		return
	}
	if jsonData.Keyword == "" {
		a.SendResponse(w, r, false, "", "", "Keyword is required")
		return
	}
	if len(jsonData.Keyword) > 100 {
		a.SendResponse(w, r, false, "", "", "Target infrastructure keyword too long (max 100 characters)")
		return
	}
	if jsonData.MinSeverity < 0 || jsonData.MinSeverity > 10 {
		a.SendResponse(w, r, false, "", "", "Invalid severity score (must be 0-10)")
		return
	}
	if jsonData.AggregationMode == "" {
		jsonData.AggregationMode = "instant"
	}
	if jsonData.AggregationMode != "instant" && jsonData.AggregationMode != "hourly" && jsonData.AggregationMode != "daily" {
		a.SendResponse(w, r, false, "", "", "Invalid aggregation mode")
		return
	}

	// Verify ownership
	var ownerID int
	err := a.Pool.QueryRow(r.Context(), "SELECT user_id FROM user_subscriptions WHERE id = $1", jsonData.ID).Scan(&ownerID)
	if err != nil {
		a.SendResponse(w, r, false, "", "", "Subscription not found")
		return
	}
	if ownerID != userID {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	_, err = a.Pool.Exec(r.Context(), `
		UPDATE user_subscriptions
		SET keyword = $1, min_severity = $2, webhook_url = $3, slack_webhook_url = $4, teams_webhook_url = $5,
		    enable_email = $6, enable_webhook = $7, enable_slack = $8, enable_teams = $9,
		    enable_browser_push = $10, aggregation_mode = $11
		WHERE id = $12 AND user_id = $13
	`, jsonData.Keyword, jsonData.MinSeverity, jsonData.WebhookURL,
		jsonData.SlackWebhookURL, jsonData.TeamsWebhookURL,
		jsonData.EnableEmail, jsonData.EnableWebhook,
		jsonData.EnableSlack, jsonData.EnableTeams, jsonData.EnableBrowserPush,
		jsonData.AggregationMode, jsonData.ID, userID)
	if err != nil {
		log.Printf("Error updating subscription: %v", err)
		a.SendResponse(w, r, false, "", "", "Error updating subscription")
		return
	}

	a.LogActivity(r.Context(), userID, "subscription_updated", fmt.Sprintf("Updated subscription ID: %d", jsonData.ID), a.GetClientIP(r), r.UserAgent())
	a.SendResponse(w, r, true, "Monitor updated successfully", "/subscriptions", "")
}

func (a *App) RSSFeedHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	minSeverityStr := r.URL.Query().Get("min_cvss")
	keyword := r.URL.Query().Get("q")

	if token == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	var userID int
	err := a.Pool.QueryRow(r.Context(), "SELECT id FROM users WHERE rss_feed_token = $1", token).Scan(&userID)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	minSeverity := 0.0
	if minSeverityStr != "" {
		minSeverity, _ = strconv.ParseFloat(minSeverityStr, 64)
	}

	escapedKeyword := escapeLikePattern(keyword)
	query := `
		SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		WHERE (
			(c.cvss_score >= us.min_severity AND (us.keyword = '' OR c.description ILIKE '%' || REPLACE(REPLACE(REPLACE(us.keyword, '\', '\\'), '%', '\%'), '_', '\_') || '%' ESCAPE '\'))
			OR
			($2 > 0 AND c.cvss_score >= $2 AND ($3 = '' OR c.description ILIKE '%' || $3 || '%' ESCAPE '\'))
		)
		ORDER BY c.published_date DESC LIMIT 50
	`
	rows, err := a.Pool.Query(r.Context(), query, userID, minSeverity, escapedKeyword)
	if err != nil {
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/rss+xml")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
  <title>Vulfixx - Advanced CVE Tracker</title>
  <link>%s</link>
  <description>Latest CVEs matching your subscriptions</description>
`, GetBaseURL())

	for rows.Next() {
		var cve struct {
			CVEID       string
			Description string
			CVSSScore   float64
			PublishedAt time.Time
		}
		if err := rows.Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.PublishedAt); err != nil {
			log.Printf("Error scanning RSS CVE: %v", err)
			continue
		}
		_, _ = fmt.Fprintf(w, `
  <item>
    <title>%s (CVSS: %s)</title>
    <link>https://nvd.nist.gov/vuln/detail/%s</link>
    <description>%s</description>
    <pubDate>%s</pubDate>
    <guid>%s</guid>
  </item>`,
			template.HTMLEscapeString(cve.CVEID),
			template.HTMLEscapeString(fmt.Sprintf("%.1f", cve.CVSSScore)),
			template.HTMLEscapeString(cve.CVEID),
			template.HTMLEscapeString(cve.Description),
			template.HTMLEscapeString(cve.PublishedAt.Format(time.RFC1123Z)),
			template.HTMLEscapeString(cve.CVEID))
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating RSS CVEs: %v", err)
	}

	_, _ = fmt.Fprintf(w, `
</channel>
</rss>`)
}

func (a *App) HandleAlertAction(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	action := r.URL.Query().Get("action")

	if token == "" || (action != "acknowledge" && action != "mute") {
		http.Error(w, "Invalid action request", http.StatusBadRequest)
		return
	}

	dataBlob, err := a.Redis.Get(r.Context(), "alert_action:"+token).Result()
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
		a.RenderTemplate(w, r, "confirm_action.html", map[string]interface{}{
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

	switch action {
	case "acknowledge":
		_, err = a.Pool.Exec(ctx, `
			INSERT INTO user_cve_status (user_id, cve_id, status)
			VALUES ($1, $2, 'in_progress')
			ON CONFLICT (user_id, cve_id) WHERE team_id IS NULL DO UPDATE SET status = 'in_progress', updated_at = CURRENT_TIMESTAMP
		`, data.UserID, data.CVEID)
		if err != nil {
			http.Error(w, "Failed to acknowledge alert", http.StatusInternalServerError)
			return
		}
		if err := a.Redis.Del(ctx, "alert_action:"+token).Err(); err != nil {
			log.Printf("Error deleting alert action from redis: %v", err)
		}
		a.LogActivity(ctx, data.UserID, "remediation", fmt.Sprintf("Acknowledged CVE ID %d via email", data.CVEID), a.GetClientIP(r), r.UserAgent())
		a.RenderTemplate(w, r, "message.html", map[string]interface{}{
			"Title":   "Alert Acknowledged",
			"Message": "Vulnerability has been marked as 'In Progress'. View it in your dashboard for further analysis.",
		})

	case "mute":
		if strings.TrimSpace(data.Keyword) == "" {
			http.Error(w, "Invalid keyword for muting", http.StatusBadRequest)
			return
		}
		_, err = a.Pool.Exec(ctx, "DELETE FROM user_subscriptions WHERE user_id = $1 AND keyword = $2", data.UserID, data.Keyword)
		if err != nil {
			http.Error(w, "Failed to mute keyword", http.StatusInternalServerError)
			return
		}
		if err := a.Redis.Del(ctx, "alert_action:"+token).Err(); err != nil {
			log.Printf("Error deleting alert action from redis: %v", err)
		}
		a.LogActivity(ctx, data.UserID, "alert_action", fmt.Sprintf("Muted keyword '%s' via email", data.Keyword), a.GetClientIP(r), r.UserAgent())
		a.RenderTemplate(w, r, "message.html", map[string]interface{}{
			"Title":   "Keyword Muted",
			"Message": fmt.Sprintf("You will no longer receive alerts for the keyword '%s'.", data.Keyword),
		})

	default:
		http.Error(w, "Unsupported action", http.StatusBadRequest)
	}
}
