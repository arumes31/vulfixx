package web

import (
	"github.com/gorilla/csrf"
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"net"

	"html/template"
	"log"
	"net/http"
	"github.com/pquerna/otp/totp"
	"strconv"
	"time"
)

var templates *template.Template

func InitTemplates() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Check if email is verified
		var isVerified bool
		err := db.Pool.QueryRow(r.Context(), "SELECT is_email_verified FROM users WHERE id = $1", userID).Scan(&isVerified)
		if err != nil || !isVerified {
			http.Error(w, "Please verify your email address to access this page.", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func LogActivity(ctx context.Context, userID int, activityType, description, ipAddress, userAgent string) {
	host, _, err := net.SplitHostPort(ipAddress)
	if err == nil {
		ipAddress = host
	}
	if len(ipAddress) > 45 {
		ipAddress = ipAddress[:45]
	}

	_, err = db.Pool.Exec(ctx, `
		INSERT INTO user_activity_logs (user_id, activity_type, description, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, activityType, description, ipAddress, userAgent)
	if err != nil {
		log.Printf("Error logging activity: %v", err)
	}
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_, ok := GetUserID(r)
	if ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		RenderTemplate(w, r, "login.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	totpCode := r.FormValue("totp_code")


	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
	}

	// Check if this is a TOTP submission for a pre-authenticated user
	preAuthUserID, hasPreAuth := session.Values["pre_auth_user_id"].(int)

	if hasPreAuth && totpCode != "" {
		// User is submitting TOTP after providing valid password
		var isTOTPEnabled bool
		var secret string
		err := db.Pool.QueryRow(r.Context(), "SELECT is_totp_enabled, COALESCE(totp_secret, '') FROM users WHERE id = $1", preAuthUserID).Scan(&isTOTPEnabled, &secret)
		if err != nil || !isTOTPEnabled || !totp.Validate(totpCode, secret) {
			RenderTemplate(w, r, "login.html", map[string]interface{}{
				"Error":       "Invalid TOTP code",
				"RequireTOTP": true,
			})
			return
		}

		// Success! Clear pre-auth and set full auth
		delete(session.Values, "pre_auth_user_id")
		session.Values["user_id"] = preAuthUserID
		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		LogActivity(r.Context(), preAuthUserID, "login", "Successful 2FA login", r.RemoteAddr, r.UserAgent())
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	user, err := auth.Login(r.Context(), email, password)
	if err != nil {
		RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Invalid credentials"})
		return
	}

	if user.IsTOTPEnabled {
		session.Values["pre_auth_user_id"] = user.ID
		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		LogActivity(r.Context(), user.ID, "login_attempt", "Password correct, awaiting 2FA", r.RemoteAddr, r.UserAgent())

		RenderTemplate(w, r, "login.html", map[string]interface{}{
			"RequireTOTP": true,
		})
		return
	}

	session.Values["user_id"] = user.ID
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	LogActivity(r.Context(), user.ID, "login", "Successful login", r.RemoteAddr, r.UserAgent())

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		RenderTemplate(w, r, "register.html", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Invalid form"})
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")

	token, err := auth.Register(context.Background(), email, password)
	if err != nil {
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}

	// Push email verification payload to redis queue
	payload, err := json.Marshal(map[string]string{
		"email": email,
		"token": token,
	})
	if err != nil {
		log.Printf("Error marshaling verification payload: %v", err)
		// Rollback: delete the user we just created since we can't send verification
		if _, delErr := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			log.Printf("Error rolling back user creation for %q: %v", email, delErr)
		}
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	if err := db.RedisClient.LPush(r.Context(), "email_verification_queue", payload).Err(); err != nil {
		log.Printf("Error enqueueing verification payload: %v", err)
		// Rollback: delete the user we just created since we can't send verification
		if _, delErr := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			log.Printf("Error rolling back user creation for %q: %v", email, delErr)
		}
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	log.Printf("Verification queued for %q", email)

	RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Registration successful. Please check your email to verify your account."})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	pageStr := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	pageSize := 20
	offset := (page - 1) * pageSize

	// Fetch total count for pagination
	countQuery := `
		SELECT COUNT(DISTINCT c.id)
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
	`
	var totalItems int
	err := db.Pool.QueryRow(context.Background(), countQuery, userID).Scan(&totalItems)
	if err != nil {
		log.Printf("Error counting CVEs: %v", err)
	}

	// Fetch CVEs not resolved/ignored by user, filtered by their subscriptions
	query := `
		SELECT DISTINCT c.id, c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		ORDER BY c.published_date DESC LIMIT $2 OFFSET $3
	`
	rows, err := db.Pool.Query(context.Background(), query, userID, pageSize, offset)
	if err != nil {
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	var kevCount, highCount int
	for rows.Next() {
		var cve models.CVE
		err := rows.Scan(&cve.ID, &cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.CISAKEV, &cve.PublishedDate)
		if err != nil {
			continue
		}
		cves = append(cves, cve)
		if cve.CISAKEV {
			kevCount++
		}
		if cve.CVSSScore >= 7.0 {
			highCount++
		}
	}

	totalPages := (totalItems + pageSize - 1) / pageSize

	RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"CVEs":        cves,
		"Total":       totalItems,
		"KevCount":    kevCount,
		"HighCount":   highCount,
		"CurrentPage": page,
		"TotalPages":  totalPages,
		"HasPrev":     page > 1,
		"HasNext":     page < totalPages,
		"PrevPage":    page - 1,
		"NextPage":    page + 1,
	})
}

func UpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CVEID  int    `json:"cve_id"`
		Status string `json:"status"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Status != "resolved" && req.Status != "ignored" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	_, err = db.Pool.Exec(context.Background(), `
		INSERT INTO user_cve_status (user_id, cve_id, status)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, cve_id) DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
	`, userID, req.CVEID, req.Status)

	if err != nil {
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"success":true}`))
}

func BulkUpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CVEIDs []int  `json:"cve_ids"`
		Status string `json:"status"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Status != "resolved" && req.Status != "ignored" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	if len(req.CVEIDs) == 0 {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
		return
	}

	// Use a transaction for bulk update
	tx, err := db.Pool.Begin(context.Background())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	for _, id := range req.CVEIDs {
		_, err = tx.Exec(context.Background(), `
			INSERT INTO user_cve_status (user_id, cve_id, status)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, cve_id) DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
		`, userID, id, req.Status)
		if err != nil {
			http.Error(w, "Failed to update status", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(context.Background()); err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"success":true}`))
}

func ActivityLogHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	query := `
		SELECT id, activity_type, description, ip_address, created_at
		FROM user_activity_logs
		WHERE user_id = $1
		ORDER BY created_at DESC LIMIT 100
	`
	rows, err := db.Pool.Query(context.Background(), query, userID)
	if err != nil {
		http.Error(w, "Error fetching activity logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var l struct {
			ID           int
			ActivityType string
			Description  string
			IPAddress    string
			CreatedAt    time.Time
		}
		if err := rows.Scan(&l.ID, &l.ActivityType, &l.Description, &l.IPAddress, &l.CreatedAt); err != nil {
			continue
		}
		logs = append(logs, map[string]interface{}{
			"ID":           l.ID,
			"ActivityType": l.ActivityType,
			"Description":  l.Description,
			"IPAddress":    l.IPAddress,
			"CreatedAt":    l.CreatedAt,
		})
	}

	RenderTemplate(w, r, "activity_log.html", map[string]interface{}{
		"Logs": logs,
	})
}

func ExportActivityLogHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	query := `
		SELECT id, activity_type, description, ip_address, created_at
		FROM user_activity_logs
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := db.Pool.Query(context.Background(), query, userID)
	if err != nil {
		http.Error(w, "Error fetching activity logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var l struct {
			ID           int
			ActivityType string
			Description  string
			IPAddress    string
			CreatedAt    time.Time
		}
		if err := rows.Scan(&l.ID, &l.ActivityType, &l.Description, &l.IPAddress, &l.CreatedAt); err != nil {
			continue
		}
		logs = append(logs, map[string]interface{}{
			"id":            l.ID,
			"activity_type": l.ActivityType,
			"description":   l.Description,
			"ip_address":    l.IPAddress,
			"created_at":    l.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment;filename=activity_log.json")
	_ = json.NewEncoder(w).Encode(logs)
}

func AlertHistoryHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	query := `
		SELECT ah.sent_at, c.cve_id, c.description, c.cvss_score
		FROM alert_history ah
		JOIN cves c ON ah.cve_id = c.id
		WHERE ah.user_id = $1
		ORDER BY ah.sent_at DESC LIMIT 100
	`
	rows, err := db.Pool.Query(context.Background(), query, userID)
	if err != nil {
		http.Error(w, "Error fetching alert history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []map[string]interface{}
	for rows.Next() {
		var a struct {
			SentAt      time.Time
			CVEID       string
			Description string
			CVSSScore   float64
		}
		if err := rows.Scan(&a.SentAt, &a.CVEID, &a.Description, &a.CVSSScore); err != nil {
			continue
		}
		alerts = append(alerts, map[string]interface{}{
			"SentAt":      a.SentAt,
			"CVEID":       a.CVEID,
			"Description": a.Description,
			"CVSSScore":   a.CVSSScore,
		})
	}

	RenderTemplate(w, r, "alert_history.html", map[string]interface{}{
		"Alerts": alerts,
	})
}

func RSSFeedHandler(w http.ResponseWriter, r *http.Request) {
	// Simple RSS feed for CVEs matching a user's subscription
	// Can be accessed via /feed?token=...
	token := r.URL.Query().Get("token")
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

	query := `
		SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		WHERE c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		ORDER BY c.published_date DESC LIMIT 50
	`
	rows, err := db.Pool.Query(context.Background(), query, userID)
	if err != nil {
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/rss+xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" ?>
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
		fmt.Fprintf(w, `
  <item>
    <title>%s (CVSS: %.1f)</title>
    <link>https://nvd.nist.gov/vuln/detail/%s</link>
    <description>%s</description>
    <pubDate>%s</pubDate>
    <guid>%s</guid>
  </item>`, cve.CVEID, cve.CVSSScore, cve.CVEID, template.HTMLEscapeString(cve.Description), cve.PublishedAt.Format(time.RFC1123Z), cve.CVEID)
	}

	fmt.Fprintf(w, `
</channel>
</rss>`)
}

func SubscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.Method == "GET" {
		query := `SELECT id, keyword, min_severity, webhook_url FROM user_subscriptions WHERE user_id = $1`
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
			if err := rows.Scan(&s.ID, &s.Keyword, &s.MinSeverity, &s.WebhookURL); err != nil {
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
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		keyword := r.FormValue("keyword")
		minSeverityStr := r.FormValue("min_severity")
		webhookUrl := r.FormValue("webhook_url")
		minSeverity, _ := strconv.ParseFloat(minSeverityStr, 64)

		_, err := db.Pool.Exec(context.Background(), `
			INSERT INTO user_subscriptions (user_id, keyword, min_severity, webhook_url)
			VALUES ($1, $2, $3, $4)
		`, userID, keyword, minSeverity, webhookUrl)
		if err != nil {
			http.Error(w, "Error saving subscription", http.StatusInternalServerError)
			return
		}
		LogActivity(r.Context(), userID, "subscription_added", "Added keyword: "+keyword, r.RemoteAddr, r.UserAgent())
		http.Redirect(w, r, "/subscriptions", http.StatusFound)
	}
}

func DeleteSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    userID, ok := GetUserID(r)
    if !ok {
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }
    subIDStr := r.FormValue("id")
    subID, err := strconv.Atoi(subIDStr)
    if err != nil {
        http.Error(w, "Invalid subscription ID", http.StatusBadRequest)
        return
    }

    if _, err = db.Pool.Exec(context.Background(), "DELETE FROM user_subscriptions WHERE id = $1 AND user_id = $2", subID, userID); err != nil {
        http.Error(w, "Error deleting subscription", http.StatusInternalServerError)
        return
    }
    LogActivity(r.Context(), userID, "subscription_deleted", "Deleted subscription ID: "+subIDStr, r.RemoteAddr, r.UserAgent())
    http.Redirect(w, r, "/subscriptions", http.StatusFound)
}


func VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	err := auth.VerifyEmail(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email verified successfully! You can now login."})
}

func ConfirmEmailChangeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	confirmed, newEmail, confirmedUserID, err := auth.ConfirmEmailChange(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	if confirmed {
		LogActivity(r.Context(), confirmedUserID, "email_change", "Successfully changed email to "+newEmail, r.RemoteAddr, r.UserAgent())
		RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email changed successfully! Please login with your new email."})
	} else {
		RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email change half-confirmed. Please confirm on the other email address as well."})
	}
}

func RenderTemplate(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	userID, ok := GetUserID(r)
	data["UserLoggedIn"] = ok
	if ok {
		data["UserID"] = userID
	}
	data["csrfField"] = csrf.TemplateField(r)
	data["csrfToken"] = csrf.Token(r)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("Error executing template %s: %v", name, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
