package web

import (

	"log"
	"net/http"
	"time"
)

func (a *App) AlertHistoryHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
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
	rows, err := a.Pool.Query(r.Context(), query, userID)
	if err != nil {
		log.Printf("failed to fetch alert history: %v", err)
		http.Error(w, "Error fetching alert history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []map[string]interface{}
	for rows.Next() {
		var al struct {
			SentAt      time.Time
			CVEID       string
			Description string
			CVSSScore   float64
		}
		if err := rows.Scan(&al.SentAt, &al.CVEID, &al.Description, &al.CVSSScore); err != nil {
			log.Printf("Error scanning alert history row: %v", err)
			continue
		}
		alerts = append(alerts, map[string]interface{}{
			"SentAt":      al.SentAt,
			"CVEID":       al.CVEID,
			"Description": al.Description,
			"CVSSScore":   al.CVSSScore,
		})
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating alert history rows: %v", err)
		http.Error(w, "Error fetching alert history", http.StatusInternalServerError)
		return
	}

	a.RenderTemplate(w, r, "alert_history.html", map[string]interface{}{
		"Alerts": alerts,
	})
}
