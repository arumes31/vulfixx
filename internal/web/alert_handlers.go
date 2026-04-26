package web

import (
	"context"
	"cve-tracker/internal/db"
	"net/http"
	"time"
)

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
