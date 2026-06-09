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
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	csrf "filippo.io/csrf/gorilla"
	"github.com/jackc/pgx/v5"
)

type contextKey string

var (
	cancelStats context.CancelFunc
	statsMu     sync.Mutex
)

func (a *App) InitTemplates() {
	if err := a.InitTemplatesWithFuncs(); err != nil {
		slog.Error("InitTemplates failed", "error", err)
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
	reqToken := r.Header.Get("X-CSRF-Token")
	if reqToken == "" {
		reqToken = r.FormValue("csrf_token")
	}
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

		// Check email verification, MFA, and onboarding status in a single query
		var isVerified bool
		var isTOTPEnabled bool
		var onboardingCompleted bool
		err := a.Pool.QueryRow(r.Context(), "SELECT is_email_verified, is_totp_enabled, onboarding_completed FROM users WHERE id = $1", userID).Scan(&isVerified, &isTOTPEnabled, &onboardingCompleted)
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

		if isTOTPEnabled {
			session, err := a.SessionStore.Get(r, "vulfixx-session")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			totpVerified, _ := session.Values["totp_verified"].(bool)
			if !totpVerified {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}

		if !onboardingCompleted {
			path := r.URL.Path
			if !strings.HasPrefix(path, "/settings") && !strings.HasPrefix(path, "/api/onboarding") && !strings.HasPrefix(path, "/static/") {
				if !isTOTPEnabled {
					http.Redirect(w, r, "/settings?info=MFA+registration+is+required+to+complete+onboarding", http.StatusFound)
				} else {
					http.Redirect(w, r, "/settings?info=Please+complete+onboarding", http.StatusFound)
				}
				return
			}
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
			slog.Error("AdminMiddleware database error", "user_id", userID, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !isAdmin {
			slog.Warn("Unauthorized admin access attempt", "user_id", userID, "ip", a.GetClientIP(r))
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		// Optionally refresh session state to keep UI consistent
		session, err := a.SessionStore.Get(r, "vulfixx-session")
		if err != nil {
			slog.Error("AdminMiddleware session error", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		session.Values["is_admin"] = isAdmin
		if err := session.Save(r, w); err != nil {
			slog.Error("AdminMiddleware session save failed", "error", err)
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
		slog.Error("Failed to log user activity", "user_id", userID, "error", err)
	} else {
		// Publish activity log event to Redis Pub/Sub for SSE streaming
		eventData := map[string]interface{}{
			"user_id":       userID,
			"activity_type": activityType,
			"description":   description,
			"ip_address":    ipAddress,
			"created_at":    time.Now().Format(time.RFC3339),
		}
		if eventJSON, err := json.Marshal(eventData); err == nil {
			_ = a.Redis.Publish(ctx, "vulfixx:activity_channel", eventJSON).Err()
		}
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

func (a *App) RenderTemplate(w http.ResponseWriter, r *http.Request, name string, data any) {
	renderData := make(map[string]interface{})

	if data != nil {
		v := reflect.ValueOf(data)
		isNilPtr := false
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				isNilPtr = true
			} else {
				v = v.Elem()
			}
		}

		if !isNilPtr {
			if v.Kind() == reflect.Map {
				for _, key := range v.MapKeys() {
					renderData[key.String()] = v.MapIndex(key).Interface()
				}
			} else if v.Kind() == reflect.Struct {
				t := v.Type()
				for i := 0; i < v.NumField(); i++ {
					field := t.Field(i)
					if field.PkgPath == "" { // exported field
						renderData[field.Name] = v.Field(i).Interface()
					}
				}
			}
		}
	}

	userID, ok := a.GetUserID(r)
	renderData["UserLoggedIn"] = ok
	if ok && userID > 0 {
		// Prevent caching of authenticated pages
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		renderData["UserID"] = userID
		renderData["IsAdmin"] = a.IsAdmin(r)

		// Onboarding status
		var onboardingCompleted bool
		err := a.Pool.QueryRow(r.Context(), "SELECT onboarding_completed FROM users WHERE id = $1", userID).Scan(&onboardingCompleted)
		if err != nil {
			slog.Error("RenderTemplate onboarding query failed", "user_id", userID, "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		renderData["OnboardingCompleted"] = onboardingCompleted

		// Fetch user's subscription count
		var subCount int
		_ = a.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM user_subscriptions WHERE user_id = $1", userID).Scan(&subCount)
		renderData["SubCount"] = subCount

		activeTeamID, ok := a.GetActiveTeamID(r)
		if !ok {
			activeTeamID = 0
		}

		// Fetch user's teams and active team name in a single query to fix N+1 issue
		var userTeams []map[string]interface{}
		var activeTeamName string

		teamRows, err := a.Pool.Query(r.Context(), `
			SELECT t.id, t.name, (tm.user_id IS NOT NULL) AS is_member
			FROM teams t
			LEFT JOIN team_members tm ON t.id = tm.team_id AND tm.user_id = $1
			WHERE tm.user_id = $1 OR t.id = $2
		`, userID, activeTeamID)

		if err != nil {
			slog.Error("RenderTemplate teams query failed", "user_id", userID, "error", err)
		} else {
			defer teamRows.Close()
			for teamRows.Next() {
				var id int
				var teamName string
				var isMember bool
				if err := teamRows.Scan(&id, &teamName, &isMember); err == nil {
					if isMember {
						userTeams = append(userTeams, map[string]interface{}{"ID": id, "Name": teamName})
					}
					if id == activeTeamID {
						activeTeamName = teamName
					}
				}
			}
			if err := teamRows.Err(); err != nil {
				slog.Error("RenderTemplate teamRows error", "user_id", userID, "error", err)
			}
			renderData["UserTeams"] = userTeams
		}

		if activeTeamID != 0 {
			renderData["ActiveTeamID"] = activeTeamID
			if activeTeamName != "" {
				renderData["ActiveTeamName"] = activeTeamName
			} else {
				renderData["ActiveTeamName"] = "Private Workspace"
			}
		} else {
			renderData["ActiveTeamID"] = 0
			renderData["ActiveTeamName"] = "Private Workspace"
		}

	}

	// Fetch global CVE stats from cache for all views
	statsCache.RLock()
	renderData["GlobalTotalCVEs"] = statsCache.total
	renderData["GlobalNewCVEs"] = statsCache.newLast24h
	statsCache.RUnlock()

	renderData["SentryDSN"] = config.AppConfig.SentryDSN

	renderData["csrfField"] = csrf.TemplateField(r) //nolint:staticcheck
	renderData["CSRFField"] = renderData["csrfField"]
	if nonce, ok := r.Context().Value(NonceKey).(string); ok {
		renderData["Nonce"] = nonce
	}
	a.TemplateMu.RLock()
	tmpl, ok := a.TemplateMap[name]
	a.TemplateMu.RUnlock()
	if !ok {
		slog.Error("Template not found", "name", name)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	buf := new(bytes.Buffer)
	if err := tmpl.ExecuteTemplate(buf, "base", renderData); err != nil {
		slog.Error("Error executing template", "name", name, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

type GlobalCVEStatsJSON struct {
	Total          int            `json:"total"`
	NewLast24h     int            `json:"new_last_24h"`
	KevCount       int            `json:"kev_count"`
	CritCount      int            `json:"crit_count"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
	TopCWEs        []CWEStat      `json:"top_cwes"`
	EpssDist       []int          `json:"epss_dist"`
	LastUpdated    time.Time      `json:"last_updated"`
}

func (a *App) getOrRefreshGlobalStats(ctx context.Context) (GlobalCVEStatsJSON, error) {
	var statsJSON GlobalCVEStatsJSON

	// Attempt to get from Redis first (Cache-Aside pattern)
	if a.Redis != nil {
		val, err := a.Redis.Get(ctx, "vulfixx:dashboard_stats").Result()
		if err == nil && val != "" {
			if err := json.Unmarshal([]byte(val), &statsJSON); err == nil {
				statsCache.Lock()
				statsCache.total = statsJSON.Total
				statsCache.newLast24h = statsJSON.NewLast24h
				statsCache.kevCount = statsJSON.KevCount
				statsCache.critCount = statsJSON.CritCount
				statsCache.severityCounts = statsJSON.SeverityCounts
				statsCache.topCWEs = statsJSON.TopCWEs
				statsCache.epssDist = statsJSON.EpssDist
				statsCache.lastUpdated = statsJSON.LastUpdated
				statsCache.Unlock()
				return statsJSON, nil
			}
		}
	}

	// Cache miss - query DB
	var total, new24h, kevCount, critCount int
	var sevCounts SeverityCounts
	epssDist := make([]int, 4)

	err := a.Pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE updated_date >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE cisa_kev = TRUE),
			COUNT(*) FILTER (WHERE cvss_score >= 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 7.0 AND cvss_score < 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 4.0 AND cvss_score < 7.0),
			COUNT(*) FILTER (WHERE cvss_score < 4.0),
			COUNT(*) FILTER (WHERE epss_score < 0.01),
			COUNT(*) FILTER (WHERE epss_score >= 0.01 AND epss_score < 0.1),
			COUNT(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5),
			COUNT(*) FILTER (WHERE epss_score >= 0.5)
		FROM cves
	`).Scan(&total, &new24h, &kevCount, &critCount, &sevCounts.Critical, &sevCounts.High, &sevCounts.Medium, &sevCounts.Low, &epssDist[0], &epssDist[1], &epssDist[2], &epssDist[3])
	if err != nil {
		return statsJSON, err
	}

	var topCWEs []CWEStat
	rowsCwe, _ := a.Pool.Query(ctx, `
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

	now := time.Now()
	statsJSON = GlobalCVEStatsJSON{
		Total:          total,
		NewLast24h:     new24h,
		KevCount:       kevCount,
		CritCount:      critCount,
		SeverityCounts: sevCounts,
		TopCWEs:        topCWEs,
		EpssDist:       epssDist,
		LastUpdated:    now,
	}

	statsCache.Lock()
	statsCache.total = total
	statsCache.newLast24h = new24h
	statsCache.kevCount = kevCount
	statsCache.critCount = critCount
	statsCache.severityCounts = sevCounts
	statsCache.topCWEs = topCWEs
	statsCache.epssDist = epssDist
	statsCache.lastUpdated = now
	statsCache.Unlock()

	// Save to Redis (Expiration = 5 minutes)
	if a.Redis != nil {
		data, err := json.Marshal(statsJSON)
		if err == nil {
			_ = a.Redis.Set(ctx, "vulfixx:dashboard_stats", string(data), 5*time.Minute).Err()
		}
	}

	slog.Info("Global stats cache refreshed", "total", total, "new_24h", new24h, "kev", kevCount, "crit", critCount)
	return statsJSON, nil
}

func (a *App) StartStatsTicker(ctx context.Context) {
	ticker := time.NewTicker(a.StatsInterval)
	defer ticker.Stop()

	// Initial refresh
	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, _ = a.getOrRefreshGlobalStats(refreshCtx)
	cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, _ = a.getOrRefreshGlobalStats(refreshCtx)
			cancel()
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
		} else if strings.Contains(lowerMsg, "conflict") {
			statusCode = http.StatusConflict
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
			slog.Error("SendResponse: JSON encode failed", "error", err)
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
