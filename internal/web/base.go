package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"cve-tracker/internal/config"
	"cve-tracker/internal/models"

	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"github.com/jackc/pgx/v5"
)

type contextKey string

var (
	cancelStats context.CancelFunc
	statsMu     sync.Mutex
)

func (a *App) InitTemplates() {
	if err := a.InitTemplatesWithFuncs(); err != nil {
		log.Printf("InitTemplates failed: %v", err)
		return
	}
	if flag.Lookup("test.v") != nil {
		return
	}
	StopStatsTicker() // Cancel previous ticker if any
	statsMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cancelStats = cancel
	statsMu.Unlock()
	go a.StartStatsTicker(ctx)
}

func StopStatsTicker() {
	statsMu.Lock()
	defer statsMu.Unlock()
	if cancelStats != nil {
		cancelStats()
		cancelStats = nil
	}
}

type globalCVEStatsCache struct {
	sync.RWMutex
	total          int
	newLast24h     int
	kevCount       int
	critCount      int
	severityCounts SeverityCounts
	topCWEs        []CWEStat
	epssDist       []int
	lastUpdated    time.Time
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type CWEStat struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

var statsCache globalCVEStatsCache

func (a *App) ValidateCSRF(r *http.Request) bool {
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return false
	}
	token, ok := session.Values["admin_csrf_token"].(string)
	if !ok || token == "" {
		return false
	}
	reqToken := r.FormValue("csrf_token")
	if reqToken == "" {
		return false
	}
	if len(token) != len(reqToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(reqToken)) == 1
}

func (a *App) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := a.GetUserID(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Check if email is verified
		var isVerified bool
		err := a.Pool.QueryRow(r.Context(), "SELECT is_email_verified FROM users WHERE id = $1", userID).Scan(&isVerified)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !isVerified {
			http.Error(w, "Please verify your email address to access this page.", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := a.GetUserID(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var isAdmin bool
		err := a.Pool.QueryRow(r.Context(), "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin)
		if err != nil {
			// #nosec G706 -- sanitized via sanitizeForLog
			log.Printf("AdminMiddleware DB ERROR: %v", sanitizeForLog(err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !isAdmin {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		// Optionally refresh session state to keep UI consistent
		session, err := a.SessionStore.Get(r, "vulfixx-session")
		if err != nil {
			log.Printf("AdminMiddleware session get error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		session.Values["is_admin"] = isAdmin
		if err := session.Save(r, w); err != nil {
			log.Printf("AdminMiddleware session save error: %v", err)
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) GetClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *App) LogActivity(ctx context.Context, userID int, activityType, description, ipAddress, userAgent string) {
	host, _, err := net.SplitHostPort(ipAddress)
	if err == nil {
		ipAddress = host
	}
	if len(ipAddress) > 45 {
		ipAddress = ipAddress[:45]
	}

	activityType = sanitizeForLog(activityType)
	description = sanitizeForLog(description)
	userAgent = sanitizeForLog(userAgent)
	ipAddress = sanitizeForLog(ipAddress)

	expiresAt := time.Now().AddDate(0, 0, 90) // 90 days retention
	_, err = a.Pool.Exec(ctx, `
		INSERT INTO user_activity_logs (user_id, activity_type, description, ip_address, user_agent, retention_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, activityType, description, ipAddress, userAgent, expiresAt)
	if err != nil {
		// #nosec G706 -- sanitized via sanitizeForLog
		log.Printf("Error logging activity: %v", sanitizeForLog(err.Error()))
	}
}

func (a *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_, ok := a.GetUserID(r)
	if ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	a.PublicDashboardHandler(w, r)
}

func (a *App) RenderTemplate(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	userID, ok := a.GetUserID(r)
	data["UserLoggedIn"] = ok
	if ok && userID > 0 {
		// Prevent caching of authenticated pages
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		data["UserID"] = userID
		data["IsAdmin"] = a.IsAdmin(r)

		// Onboarding status
		var onboardingCompleted bool
		err := a.Pool.QueryRow(r.Context(), "SELECT onboarding_completed FROM users WHERE id = $1", userID).Scan(&onboardingCompleted)
		if err != nil {
			// #nosec G706 -- sanitized via sanitizeForLog
			log.Printf("RenderTemplate onboarding query ERR (UserID: %d): %v", userID, sanitizeForLog(err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		data["OnboardingCompleted"] = onboardingCompleted

		// Fetch user's subscription count
		var subCount int
		_ = a.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1", userID).Scan(&subCount)
		data["SubCount"] = subCount

		// Fetch user's teams
		teamRows, err := a.Pool.Query(r.Context(), `
			SELECT t.id, t.name 
			FROM teams t
			JOIN team_members tm ON t.id = tm.team_id
			WHERE tm.user_id = $1
		`, userID)
		if err != nil {
			log.Printf("RenderTemplate teams query ERR: %v", err)
		} else {
			defer teamRows.Close()
			var teams []map[string]interface{}
			for teamRows.Next() {
				var id int
				var teamName string
				if err := teamRows.Scan(&id, &teamName); err == nil {
					teams = append(teams, map[string]interface{}{"ID": id, "Name": teamName})
				}
			}
			if err := teamRows.Err(); err != nil {
				log.Printf("RenderTemplate teamRows ERR: %v", err)
			}
			data["UserTeams"] = teams
		}

		activeTeamID, ok := a.GetActiveTeamID(r)
		if ok && activeTeamID != 0 {
			var teamName string
			err := a.Pool.QueryRow(r.Context(), "SELECT name FROM teams WHERE id = $1", activeTeamID).Scan(&teamName)
			if err != nil {
				log.Printf("Error fetching active team name: %v", err)
			} else {
				data["ActiveTeamName"] = teamName
			}
			data["ActiveTeamID"] = activeTeamID
		} else {
			data["ActiveTeamID"] = 0
			data["ActiveTeamName"] = "Private Workspace"
		}

	}

	// Fetch global CVE stats from cache for all views
	statsCache.RLock()
	data["GlobalTotalCVEs"] = statsCache.total
	data["GlobalNewCVEs"] = statsCache.newLast24h
	statsCache.RUnlock()

	data["SentryDSN"] = config.AppConfig.SentryDSN

	data["csrfField"] = csrf.TemplateField(r)
	data["CSRFField"] = data["csrfField"]
	if nonce, ok := r.Context().Value(NonceKey).(string); ok {
		data["Nonce"] = nonce
	}
	a.TemplateMu.RLock()
	tmpl, ok := a.TemplateMap[name]
	a.TemplateMu.RUnlock()
	if !ok {
		log.Printf("Template %s not found", name)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	buf := new(bytes.Buffer)
	if err := tmpl.ExecuteTemplate(buf, "base", data); err != nil {
		log.Printf("Error executing template %s: %v", name, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

func (a *App) StartStatsTicker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	refresh := func() {
		refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		var total, new24h, kevCount, critCount int
		_ = a.Pool.QueryRow(refreshCtx, "SELECT COUNT(*) FROM cves").Scan(&total)
		_ = a.Pool.QueryRow(refreshCtx, "SELECT COUNT(*) FROM cves WHERE updated_date >= NOW() - INTERVAL '24 hours'").Scan(&new24h)
		_ = a.Pool.QueryRow(refreshCtx, "SELECT COUNT(*) FROM cves WHERE cisa_kev = TRUE").Scan(&kevCount)
		_ = a.Pool.QueryRow(refreshCtx, "SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0").Scan(&critCount)

		var sevCounts SeverityCounts
		_ = a.Pool.QueryRow(refreshCtx, `
			SELECT 
				COUNT(*) FILTER (WHERE cvss_score >= 9.0),
				COUNT(*) FILTER (WHERE cvss_score >= 7.0 AND cvss_score < 9.0),
				COUNT(*) FILTER (WHERE cvss_score >= 4.0 AND cvss_score < 7.0),
				COUNT(*) FILTER (WHERE cvss_score < 4.0)
			FROM cves
		`).Scan(&sevCounts.Critical, &sevCounts.High, &sevCounts.Medium, &sevCounts.Low)

		var topCWEs []CWEStat
		rowsCwe, _ := a.Pool.Query(refreshCtx, `
			SELECT cwe_id, COALESCE(MAX(cwe_name), 'Unknown'), COUNT(*) as cnt 
			FROM cves 
			WHERE cwe_id IS NOT NULL AND cwe_id != '' 
			GROUP BY cwe_id 
			ORDER BY cnt DESC 
			LIMIT 15
		`)
		if rowsCwe != nil {
			for rowsCwe.Next() {
				var s CWEStat
				if err := rowsCwe.Scan(&s.ID, &s.Name, &s.Count); err == nil {
					s.Name = models.GetCWEName(s.ID, s.Name)
					topCWEs = append(topCWEs, s)
				}
			}
			rowsCwe.Close()
		}

		epssDist := make([]int, 4)
		_ = a.Pool.QueryRow(refreshCtx, `
			SELECT 
				COUNT(*) FILTER (WHERE epss_score < 0.01),
				COUNT(*) FILTER (WHERE epss_score >= 0.01 AND epss_score < 0.1),
				COUNT(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5),
				COUNT(*) FILTER (WHERE epss_score >= 0.5)
			FROM cves
		`).Scan(&epssDist[0], &epssDist[1], &epssDist[2], &epssDist[3])

		statsCache.Lock()
		statsCache.total = total
		statsCache.newLast24h = new24h
		statsCache.kevCount = kevCount
		statsCache.critCount = critCount
		statsCache.severityCounts = sevCounts
		statsCache.topCWEs = topCWEs
		statsCache.epssDist = epssDist
		statsCache.lastUpdated = time.Now()
		statsCache.Unlock()
		log.Printf("Global stats cache refreshed: Total=%d, New=%d, KEV=%d, Crit=%d", total, new24h, kevCount, critCount)
	}

	// Initial refresh
	refresh()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
func (a *App) SendResponse(w http.ResponseWriter, r *http.Request, success bool, message string, redirect string, errMsg string) {
	statusCode := http.StatusOK
	if !success {
		statusCode = http.StatusBadRequest
		lowerMsg := strings.ToLower(errMsg)
		if strings.Contains(lowerMsg, "unauthorized") {
			statusCode = http.StatusUnauthorized
		} else if strings.Contains(lowerMsg, "forbidden") {
			statusCode = http.StatusForbidden
		} else if strings.Contains(lowerMsg, "not found") {
			statusCode = http.StatusNotFound
		} else if strings.Contains(lowerMsg, "internal server error") {
			statusCode = http.StatusInternalServerError
		} else if strings.Contains(lowerMsg, "method not allowed") {
			statusCode = http.StatusMethodNotAllowed
		}
	}

	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		resp := map[string]interface{}{
			"success": success,
		}
		if message != "" {
			resp["message"] = message
		}
		if redirect != "" {
			resp["redirect"] = redirect
		}
		if errMsg != "" {
			resp["error"] = errMsg
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("SendResponse: JSON encode error: %v", err)
		}
		return
	}

	if !success {
		http.Error(w, errMsg, statusCode)
		return
	}
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func sanitizeForLog(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, string(rune(0)), "")
	return s
}
