package web

import (
	"database/sql"
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
	skippedRows := 0
	for rows.Next() {
		var sentAt time.Time
		var cveID string
		var description sql.NullString
		var cvssScore sql.NullFloat64

		if err := rows.Scan(&sentAt, &cveID, &description, &cvssScore); err != nil {
			log.Printf("Error scanning alert history row: %v", err)
			skippedRows++
			continue
		}
		alerts = append(alerts, map[string]interface{}{
			"SentAt":      sentAt,
			"CVEID":       cveID,
			"Description": description.String,
			"CVSSScore":   cvssScore.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating alert history rows: %v", err)
		http.Error(w, "Error fetching alert history", http.StatusInternalServerError)
		return
	}

	if skippedRows > 0 {
		log.Printf("Skipped %d rows due to scan errors", skippedRows)
	}

	a.RenderTemplate(w, r, "alert_history.html", map[string]interface{}{
		"Alerts":      alerts,
		"SkippedRows": skippedRows,
	})
}
