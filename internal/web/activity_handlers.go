package web

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/redis/go-redis/v9"
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

// ActivityStreamHandler streams real-time user activity logs using Server-Sent Events (SSE).
// @Summary Stream User Activity Events
// @Description Stream real-time user activity logs for the authenticated user using Server-Sent Events (SSE).
// @Tags Activity
// @Produce text/event-stream
// @Success 200 {string} string "SSE Event Stream"
// @Router /api/activity/stream [get]
func (a *App) ActivityStreamHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sub, ok := a.Redis.(interface {
		Subscribe(ctx context.Context, channels ...string) *redis.PubSub
	})
	if !ok {
		http.Error(w, "Redis subscription unsupported", http.StatusInternalServerError)
		return
	}

	pubsub := sub.Subscribe(r.Context(), "vulfixx:activity_channel")
	defer pubsub.Close()

	ch := pubsub.Channel()

	// Send initial comment to establish connection
	_, _ = fmt.Fprint(w, ": ok\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var event map[string]interface{}
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				continue
			}

			// Filter: only send to the authenticated user
			eventUserID, _ := event["user_id"].(float64)
			if int(eventUserID) != userID {
				continue
			}

			// Send event
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg.Payload)
			flusher.Flush()
		}
	}
}
