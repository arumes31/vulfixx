package web

import (
	"github.com/gorilla/csrf"
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/json"

	"html/template"
	"log"
	"net/http"
	"github.com/pquerna/otp/totp"
	"strconv"
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

	r.ParseForm()
	email := r.FormValue("email")
	password := r.FormValue("password")
	totpCode := r.FormValue("totp_code")


	session, _ := store.Get(r, "session-name")

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
		session.Save(r, w)
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
		session.Save(r, w)

		RenderTemplate(w, r, "login.html", map[string]interface{}{
			"RequireTOTP": true,
		})
		return
	}

	session.Values["user_id"] = user.ID
	session.Save(r, w)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		RenderTemplate(w, r, "register.html", nil)
		return
	}

	r.ParseForm()
	email := r.FormValue("email")
	password := r.FormValue("password")

	token, err := auth.Register(context.Background(), email, password)
	if err != nil {
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}

	// Push email verification payload to redis queue
	payload, _ := json.Marshal(map[string]string{
		"email": email,
		"token": token,
	})
	db.RedisClient.LPush(r.Context(), "email_verification_queue", payload)
	log.Printf("Verification queued for %s\n", email)

	RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Registration successful. Please check your email to verify your account."})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := GetUserID(r)

	// Fetch CVEs not resolved/ignored by user, filtered by their subscriptions
	query := `
		SELECT DISTINCT c.id, c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		ORDER BY c.published_date DESC LIMIT 50
	`
	rows, err := db.Pool.Query(context.Background(), query, userID)
	if err != nil {
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var cve models.CVE
		err := rows.Scan(&cve.ID, &cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.CISAKEV, &cve.PublishedDate)
		if err != nil {
			continue
		}
		cves = append(cves, cve)
	}

	RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"CVEs": cves,
	})
}

func UpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _ := GetUserID(r)

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
	w.Write([]byte(`{"success":true}`))
}

func SubscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := GetUserID(r)
	if r.Method == "GET" {
		query := `SELECT id, keyword, min_severity, webhook_url FROM user_subscriptions WHERE user_id = $1`
		rows, _ := db.Pool.Query(context.Background(), query, userID)
		defer rows.Close()
		var subs []models.UserSubscription
		for rows.Next() {
			var s models.UserSubscription
			rows.Scan(&s.ID, &s.Keyword, &s.MinSeverity, &s.WebhookURL)
			subs = append(subs, s)
		}
		RenderTemplate(w, r, "subscriptions.html", map[string]interface{}{"Subscriptions": subs})
		return
	}
	if r.Method == "POST" {
		r.ParseForm()
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
		http.Redirect(w, r, "/subscriptions", http.StatusFound)
	}
}

func DeleteSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    userID, _ := GetUserID(r)
    subIDStr := r.FormValue("id")
    subID, _ := strconv.Atoi(subIDStr)

    _, err := db.Pool.Exec(context.Background(), "DELETE FROM user_subscriptions WHERE id = $1 AND user_id = $2", subID, userID)
    if err != nil {
        http.Error(w, "Error deleting subscription", http.StatusInternalServerError)
        return
    }
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
	templates.ExecuteTemplate(w, name, data)
}
