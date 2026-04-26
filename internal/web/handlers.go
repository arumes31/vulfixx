package web

import (
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"

	"github.com/gorilla/csrf"
	"github.com/pquerna/otp/totp"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var templateMap map[string]*template.Template

func InitTemplates() {
	InitTemplatesWithFuncs()
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
		if err != nil {
			log.Printf("AuthMiddleware DB ERROR: userID=%v, path=%s, err=%v", userID, r.URL.Path, err)
			http.Error(w, "Please verify your email address to access this page.", http.StatusForbidden)
			return
		}
		if !isVerified {
			log.Printf("AuthMiddleware NOT VERIFIED: userID=%v, path=%s", userID, r.URL.Path)
			http.Error(w, "Please verify your email address to access this page.", http.StatusForbidden)
			return
		}
		log.Printf("AuthMiddleware SUCCESS: userID=%v, path=%s", userID, r.URL.Path)

		next.ServeHTTP(w, r)
	})
}

func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var isAdmin bool
		err := db.Pool.QueryRow(r.Context(), "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin)
		if err != nil || !isAdmin {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		// Optionally refresh session state to keep UI consistent
		session, _ := store.Get(r, "session-name")
		session.Values["is_admin"] = isAdmin
		_ = session.Save(r, w)

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

		var isAdmin bool
		_ = db.Pool.QueryRow(r.Context(), "SELECT is_admin FROM users WHERE id = $1", preAuthUserID).Scan(&isAdmin)
		session.Values["is_admin"] = isAdmin

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
	session.Values["is_admin"] = user.IsAdmin
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
			log.Printf("Error rolling back user creation for %q: %v", email, delErr) // #nosec G706
		}
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	if err := db.RedisClient.LPush(r.Context(), "email_verification_queue", payload).Err(); err != nil {
		log.Printf("Error enqueueing verification payload: %v", err)
		// Rollback: delete the user we just created since we can't send verification
		if _, delErr := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			log.Printf("Error rolling back user creation for %q: %v", email, delErr) // #nosec G706
		}
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	log.Printf("Verification queued for %q", email) // #nosec G706

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

	searchQuery := r.URL.Query().Get("q")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")
	searchAll := r.URL.Query().Get("all") == "true"
	statusFilter := r.URL.Query().Get("status") // e.g. 'active', 'in_progress', 'resolved'
	kevOnly := r.URL.Query().Get("kev") == "true"
	minCvssStr := r.URL.Query().Get("min_cvss")
	maxCvssStr := r.URL.Query().Get("max_cvss")

	minCvss, _ := strconv.ParseFloat(minCvssStr, 64)
	maxCvss, _ := strconv.ParseFloat(maxCvssStr, 64)
	if maxCvss == 0 {
		maxCvss = 10.0
	}

	var totalItems, kevCount int

	metricsQuery := `
		SELECT
			COUNT(DISTINCT c.id) as total_cves,
			COUNT(DISTINCT CASE WHEN c.cisa_kev = true THEN c.id END) as kev_count,
			COUNT(DISTINCT CASE WHEN c.cvss_score >= 9.0 THEN c.id END) as critical_count,
			COUNT(DISTINCT CASE WHEN ucs.status = 'in_progress' THEN c.id END) as in_progress_count
		FROM cves c
	`

	if !searchAll {
		metricsQuery += `
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		`
	} else {
		metricsQuery += `
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (1=1)
		`
		allowedStatuses := map[string]bool{
			"active":        true,
			"in_progress":   true,
			"waiting_patch": true,
			"resolved":      true,
			"ignored":       true,
		}

		if statusFilter == "" || statusFilter == "active" {
			metricsQuery += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		} else if allowedStatuses[statusFilter] {
			metricsQuery += " AND ucs.status = $10 " // Placeholder for statusFilter
		}
	}

	metricsQuery += `
		  AND ($2 = '' OR c.cve_id ILIKE '%' || $2 || '%' OR c.description ILIKE '%' || $2 || '%')
	`
	if kevOnly {
		metricsQuery += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		metricsQuery += fmt.Sprintf(" AND c.cvss_score >= %f ", minCvss)
	}
	if maxCvss < 10 {
		metricsQuery += fmt.Sprintf(" AND c.cvss_score <= %f ", maxCvss)
	}

	args := []interface{}{userID, searchQuery}

	if startDate != "" {
		metricsQuery += ` AND c.published_date >= $3`
		args = append(args, startDate)
	} else {
		metricsQuery += ` AND (1=1 OR $3 = '')`
		args = append(args, "")
	}

	if endDate != "" {
		metricsQuery += ` AND c.published_date <= $4`
		args = append(args, endDate)
	} else {
		metricsQuery += ` AND (1=1 OR $4 = '')`
		args = append(args, "")
	}

	// For the status filter placeholder if it was added
	if strings.Contains(metricsQuery, "$10") {
		args = append(args, statusFilter)
	} else {
		// Padding to keep args aligned if we ever add more positional params
		args = append(args, "")
	}

	var critCount, progressCount int
	err := db.Pool.QueryRow(context.Background(), metricsQuery, args...).Scan(&totalItems, &kevCount, &critCount, &progressCount)
	if err != nil {
		log.Printf("Error counting metrics: %v", err)
	}

	query := `
		SELECT DISTINCT c.id, c.cve_id, c.description, c.cvss_score, c.vector_string, c.cisa_kev, c.published_date, c.updated_date, COALESCE(ucs.status, 'active') as status, c."references", ucn.notes
		FROM cves c
		LEFT JOIN user_cve_notes ucn ON c.id = ucn.cve_id AND ucn.user_id = $1
	`

	if !searchAll {
		query += `
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		`
	} else {
		query += `
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (1=1)
		`
		if statusFilter == "" || statusFilter == "active" {
			query += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		} else {
			// Reuse the allowlist check from above
			allowedStatuses := map[string]bool{"active":true,"in_progress":true,"waiting_patch":true,"resolved":true,"ignored":true}
			if allowedStatuses[statusFilter] {
				query += " AND ucs.status = $10 "
			}
		}
	}

	query += `
		  AND ($2 = '' OR c.cve_id ILIKE '%' || $2 || '%' OR c.description ILIKE '%' || $2 || '%')
	`
	if kevOnly {
		query += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		query += fmt.Sprintf(" AND c.cvss_score >= %f ", minCvss)
	}
	if maxCvss < 10 {
		query += fmt.Sprintf(" AND c.cvss_score <= %f ", maxCvss)
	}

	if startDate != "" {
		query += ` AND c.published_date >= $3`
	} else {
		query += ` AND (1=1 OR $3 = '')`
	}

	if endDate != "" {
		query += ` AND c.published_date <= $4`
	} else {
		query += ` AND (1=1 OR $4 = '')`
	}

	query += ` ORDER BY c.published_date DESC LIMIT $5 OFFSET $6`

	// Ensure args matches placeholders $1..$6 + $10
	// args is [userID, searchQuery, startDate, endDate]
	// and we added pageSize, offset
	args = append(args, pageSize, offset)
	// If $10 is used, ensure it's at index 9 (10th element)
	if strings.Contains(query, "$10") {
		for len(args) < 9 {
			args = append(args, "")
		}
		args = append(args, statusFilter)
	}

	rows, err := db.Pool.Query(context.Background(), query, args...)
	if err != nil {
		log.Printf("Error fetching CVEs: %v", err)
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var notes sql.NullString
		err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes)
		if err != nil {
			log.Printf("Error scanning CVE: %v", err)
			continue
		}
		c.Notes = notes.String
		cves = append(cves, c)
	}

	// Threat Level Calculation
	threatLevel := "LOW"
	threatColor := "text-primary"
	if kevCount > 5 || critCount > 10 {
		threatLevel = "CRITICAL"
		threatColor = "text-error"
	} else if kevCount > 0 || critCount > 0 {
		threatLevel = "HIGH"
		threatColor = "text-error"
	} else if progressCount > 0 {
		threatLevel = "ELEVATED"
		threatColor = "text-tertiary"
	}
	// Severity Distribution - Calculate across entire dataset (Issue 3)
	severityDist := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	distQuery := `
		SELECT c.cvss_score 
		FROM cves c 
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (1=1)
	`
	distArgs := []interface{}{userID}
	if !searchAll {
		distQuery += ` AND EXISTS (SELECT 1 FROM user_subscriptions us WHERE us.user_id = $1 AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%') AND c.cvss_score >= us.min_severity)`
	} else if statusFilter == "" || statusFilter == "active" {
		distQuery += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
	} else {
		allowedStatuses := map[string]bool{"active":true,"in_progress":true,"waiting_patch":true,"resolved":true,"ignored":true}
		if allowedStatuses[statusFilter] {
			distQuery += " AND ucs.status = $2 "
			distArgs = append(distArgs, statusFilter)
		}
	}

	distRows, err := db.Pool.Query(context.Background(), distQuery, distArgs...)
	if err == nil {
		defer distRows.Close()
		for distRows.Next() {
			var score float64
			if err := distRows.Scan(&score); err == nil {
				if score >= 9.0 {
					severityDist["Critical"]++
				} else if score >= 7.0 {
					severityDist["High"]++
				} else if score >= 4.0 {
					severityDist["Medium"]++
				} else {
					severityDist["Low"]++
				}
			}
		}
	} else {
		log.Printf("Dashboard: distribution query failed: %v", err)
	}

	totalPages := (totalItems + pageSize - 1) / pageSize

	RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"CVEs":          cves,
		"Total":         totalItems,
		"KevCount":      kevCount,
		"CritCount":     critCount,
		"ProgressCount": progressCount,
		"ThreatLevel":   threatLevel,
		"ThreatColor":   threatColor,
		"SeverityDist":  severityDist,
		"CurrentPage":   page,
		"TotalPages":    totalPages,
		"HasPrev":       page > 1,
		"HasNext":       page < totalPages,
		"PrevPage":      page - 1,
		"NextPage":      page + 1,
		"Query":         searchQuery,
		"StartDate":     startDate,
		"EndDate":       endDate,
		"SearchAll":     searchAll,
		"StatusFilter":  statusFilter,
		"KevOnly":       kevOnly,
		"MinCvss":       minCvssStr,
		"MaxCvss":       maxCvssStr,
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

	validStatuses := map[string]bool{
		"active":         true,
		"in_progress":    true,
		"waiting_patch":  true,
		"resolved":       true,
		"ignored":        true,
	}
	if !validStatuses[req.Status] {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	if req.Status == "active" {
		_, err = db.Pool.Exec(context.Background(), `
			DELETE FROM user_cve_status WHERE user_id = $1 AND cve_id = $2
		`, userID, req.CVEID)
	} else {
		_, err = db.Pool.Exec(context.Background(), `
			INSERT INTO user_cve_status (user_id, cve_id, status)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, cve_id) DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
		`, userID, req.CVEID, req.Status)
	}

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

	ctx := r.Context()
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
		LogActivity(ctx, data.UserID, "alert_action", fmt.Sprintf("Acknowledged CVE ID %d via email", data.CVEID), r.RemoteAddr, r.UserAgent())
		RenderTemplate(w, r, "message.html", map[string]interface{}{
			"Title":   "Alert Acknowledged",
			"Message": "Vulnerability has been marked as 'In Progress'. View it in your dashboard for further analysis.",
		})

	case "mute":
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

	// Delete token after use
	db.RedisClient.Del(ctx, "alert_action:"+token)
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
			http.Error(w, "Error parsing form", http.StatusBadRequest)
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
		data["IsAdmin"] = IsAdmin(r)

		// Fetch global CVE stats for the sidebar/navbar
		var totalCached, newLast24h int
		_ = db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM cves").Scan(&totalCached)
		_ = db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM cves WHERE updated_date >= NOW() - INTERVAL '24 hours'").Scan(&newLast24h)
		data["GlobalTotalCVEs"] = totalCached
		data["GlobalNewCVEs"] = newLast24h
	}
	data["csrfField"] = csrf.TemplateField(r)
	tmpl, ok := templateMap[name]
	if !ok {
		log.Printf("Template %s not found", name)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("Error executing template %s: %v", name, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func AdminUserManagementHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Pool.Query(r.Context(), "SELECT id, email, is_email_verified, is_admin, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.IsEmailVerified, &u.IsAdmin, &u.CreatedAt); err != nil {
			continue
		}
		users = append(users, u)
	}

	RenderTemplate(w, r, "admin_users.html", map[string]interface{}{
		"Users": users,
	})
}

func AdminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	idStr := r.FormValue("id")
	if idStr == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Prevent admin from deleting themselves
	currentUserID, _ := GetUserID(r)
	if id == currentUserID {
		http.Error(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}

	res, err := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE id = $1 AND is_admin = FALSE", id)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	if res.RowsAffected() == 0 {
		http.Error(w, "User not found or cannot be deleted", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func AssetsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "GET" {
		rows, err := db.Pool.Query(r.Context(), `
			SELECT a.id, a.name, a.type, a.created_at, 
			       COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}')
			FROM assets a
			LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
			WHERE a.user_id = $1
			GROUP BY a.id
			ORDER BY a.created_at DESC
		`, userID)
		if err != nil {
			log.Printf("Error fetching assets: %v", err)
			http.Error(w, "Error fetching assets", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type AssetWithKeywords struct {
			models.Asset
			Keywords []string
		}
		var assets []AssetWithKeywords
		for rows.Next() {
			var a AssetWithKeywords
			if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.CreatedAt, &a.Keywords); err != nil {
				continue
			}
			assets = append(assets, a)
		}
		RenderTemplate(w, r, "assets.html", map[string]interface{}{"Assets": assets})
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		assetType := r.FormValue("type")
		keywords := r.FormValue("keywords")

		// Validate inputs (Issue 5)
		if len(name) < 1 || len(name) > 255 {
			http.Error(w, "Asset name must be between 1 and 255 characters", http.StatusBadRequest)
			return
		}
		allowedTypes := map[string]bool{
			"Server":   true,
			"Software": true,
			"Network":  true,
			"Cloud":    true,
			"IoT":      true,
		}
		if !allowedTypes[assetType] {
			http.Error(w, "Invalid asset category", http.StatusBadRequest)
			return
		}

		tx, err := db.Pool.Begin(r.Context())
		if err != nil {
			http.Error(w, "Error starting transaction", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var assetID int
		err = tx.QueryRow(r.Context(), `
			INSERT INTO assets (user_id, name, type) VALUES ($1, $2, $3) RETURNING id
		`, userID, name, assetType).Scan(&assetID)
		if err != nil {
			http.Error(w, "Error creating asset", http.StatusInternalServerError)
			return
		}

		if keywords != "" {
			kwList := strings.Split(keywords, ",")
			for _, kw := range kwList {
				kw = strings.TrimSpace(kw)
				if kw != "" {
					_, err = tx.Exec(r.Context(), `
						INSERT INTO asset_keywords (asset_id, keyword) VALUES ($1, $2)
						ON CONFLICT DO NOTHING
					`, assetID, kw)
					if err != nil {
						http.Error(w, "Error adding keyword", http.StatusInternalServerError)
						return
					}
				}
			}
		}

		if err = tx.Commit(r.Context()); err != nil {
			http.Error(w, "Error committing transaction", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/assets", http.StatusFound)
	}
}

func DeleteAssetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	idStr := r.FormValue("id")
	// Sanitize for logging (Issue 706)
	safeIdStr := strings.ReplaceAll(strings.ReplaceAll(idStr, "\n", ""), "\r", "")
	assetID, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("DeleteAsset: invalid asset ID %q: %v", safeIdStr, err)
		http.Error(w, "Invalid asset ID", http.StatusBadRequest)
		return
	}
	_, err = db.Pool.Exec(r.Context(), "DELETE FROM assets WHERE id = $1 AND user_id = $2", assetID, userID)
	if err != nil {
		http.Error(w, "Error deleting asset", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/assets", http.StatusFound)
}

func UpdateCVENoteHandler(w http.ResponseWriter, r *http.Request) {
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
		CVEID int    `json:"cve_id"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Pool.Exec(r.Context(), `
		INSERT INTO user_cve_notes (user_id, cve_id, notes, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, cve_id) DO UPDATE SET
			notes = EXCLUDED.notes,
			updated_at = NOW()
	`, userID, req.CVEID, req.Notes)
	if err != nil {
		log.Printf("Error updating note: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
