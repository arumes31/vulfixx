package web

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"net/http"
	"time"
)

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
