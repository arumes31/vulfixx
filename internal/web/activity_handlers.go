package web

import (
	"cve-tracker/internal/models"
	"encoding/json"
	"log"
	"net/http"
)

func (a *App) ActivityLogHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
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
	rows, err := a.Pool.Query(r.Context(), query, userID)
	if err != nil {
		log.Printf("Error querying activity logs: %v", err)
		http.Error(w, "Error fetching activity logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	logs := []models.ActivityLog{}
	for rows.Next() {
		var l models.ActivityLog
		if err := rows.Scan(&l.ID, &l.ActivityType, &l.Description, &l.IPAddress, &l.CreatedAt); err != nil {
			log.Printf("Error scanning activity log: %v", err)
			continue
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating activity logs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	a.RenderTemplate(w, r, "activity_log.html", map[string]interface{}{
		"Logs": logs,
	})
}

func (a *App) ExportActivityLogHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","message":"authentication required"}`))
		return
	}

	query := `
		SELECT id, activity_type, description, ip_address, created_at
		FROM user_activity_logs
		WHERE user_id = $1
		ORDER BY created_at DESC LIMIT 1000
	`
	rows, err := a.Pool.Query(r.Context(), query, userID)
	if err != nil {
		log.Printf("Error querying activity logs for export: %v", err)
		http.Error(w, "Error fetching activity logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	logs := []models.ActivityLog{}
	for rows.Next() {
		var l models.ActivityLog
		if err := rows.Scan(&l.ID, &l.ActivityType, &l.Description, &l.IPAddress, &l.CreatedAt); err != nil {
			log.Printf("Error scanning activity log for export: %v", err)
			continue
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating activity logs for export: %v", err)
		http.Error(w, "Error fetching activity logs", http.StatusInternalServerError)
		return
	}

	buf, err := json.Marshal(logs)
	if err != nil {
		log.Printf("Error encoding activity log export: %v", err)
		http.Error(w, "Error generating export", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"activity_log.json\"")
	_, _ = w.Write(buf)
}
