package web

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
)

var templateMap map[string]*template.Template

func InitTemplates() {
	InitTemplatesWithFuncs()
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
			var teams []map[string]interface{}
			for teamRows.Next() {
				var id int
				var name string
				if err := teamRows.Scan(&id, &name); err == nil {
					teams = append(teams, map[string]interface{}{"ID": id, "Name": name})
				}
			}
			teamRows.Close()
			data["UserTeams"] = teams
		}

		activeTeamID, ok := GetActiveTeamID(r)
		if ok && activeTeamID != 0 {
			var teamName string
			_ = db.Pool.QueryRow(r.Context(), "SELECT name FROM teams WHERE id = $1", activeTeamID).Scan(&teamName)
			data["ActiveTeamID"] = activeTeamID
			data["ActiveTeamName"] = teamName
		} else {
			data["ActiveTeamID"] = 0
			data["ActiveTeamName"] = "Private Workspace"
		}

		// Fetch global CVE stats
		statsCache.RLock()
		if time.Since(statsCache.lastUpdated) > 5*time.Minute {
			statsCache.RUnlock()
			statsCache.Lock()
			if time.Since(statsCache.lastUpdated) > 5*time.Minute {
				_ = db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM cves").Scan(&statsCache.total)
				_ = db.Pool.QueryRow(r.Context(), "SELECT COUNT(*) FROM cves WHERE updated_date >= NOW() - INTERVAL '24 hours'").Scan(&statsCache.newLast24h)
				statsCache.lastUpdated = time.Now()
			}
			data["GlobalTotalCVEs"] = statsCache.total
			data["GlobalNewCVEs"] = statsCache.newLast24h
			statsCache.Unlock()
		} else {
			data["GlobalTotalCVEs"] = statsCache.total
			data["GlobalNewCVEs"] = statsCache.newLast24h
			statsCache.RUnlock()
		}
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
	http.Redirect(w, r, redirect, http.StatusFound)
}
