package web

import (
	"bytes"
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"github.com/jackc/pgx/v5"
)

var templateMap map[string]*template.Template

var cancelStats context.CancelFunc

func InitTemplates() {
	InitTemplatesWithFuncs()
	ctx, cancel := context.WithCancel(context.Background())
	cancelStats = cancel
	go StartStatsTicker(ctx)
}

func StopStatsTicker() {
	if cancelStats != nil {
		cancelStats()
	}
}

type globalCVEStatsCache struct {
	sync.RWMutex
	total       int
	newLast24h  int
	lastUpdated time.Time
}

var statsCache globalCVEStatsCache

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

func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var isAdmin bool
		err := db.Pool.QueryRow(r.Context(), "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin)
		if err != nil {
			log.Printf("AdminMiddleware DB ERROR: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !isAdmin {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		// Optionally refresh session state to keep UI consistent
		session, _ := store.Get(r, "vulfixx-session")
		session.Values["is_admin"] = isAdmin
		if err := session.Save(r, w); err != nil {
			log.Printf("AdminMiddleware session save error: %v", err)
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
	PublicDashboardHandler(w, r)
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

		// Fetch user's teams
		teamRows, err := db.Pool.Query(r.Context(), `
			SELECT t.id, t.name 
			FROM teams t
			JOIN team_members tm ON t.id = tm.team_id
			WHERE tm.user_id = $1
		`, userID)
		if err == nil {
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

		activeTeamID, ok := GetActiveTeamID(r)
		if ok && activeTeamID != 0 {
			var teamName string
			err := db.Pool.QueryRow(r.Context(), "SELECT name FROM teams WHERE id = $1", activeTeamID).Scan(&teamName)
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

	data["csrfField"] = csrf.TemplateField(r)
	if nonce, ok := r.Context().Value("nonce").(string); ok {
		data["Nonce"] = nonce
	}
	tmpl, ok := templateMap[name]
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

func StartStatsTicker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	refresh := func() {
		var total, new24h int
		err1 := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cves").Scan(&total)
		err2 := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cves WHERE updated_date >= NOW() - INTERVAL '24 hours'").Scan(&new24h)
		
		if err1 == nil && err2 == nil {
			statsCache.Lock()
			statsCache.total = total
			statsCache.newLast24h = new24h
			statsCache.lastUpdated = time.Now()
			statsCache.Unlock()
			log.Printf("Global stats cache refreshed: Total=%d, New=%d", total, new24h)
		} else {
			log.Printf("Error refreshing global stats: %v, %v", err1, err2)
		}
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
func SendResponse(w http.ResponseWriter, r *http.Request, success bool, message string, redirect string, errMsg string) {
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
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
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	if !success {
		http.Error(w, errMsg, http.StatusBadRequest)
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
