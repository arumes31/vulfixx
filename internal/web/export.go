package web

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
)

func ExportCVEsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	query := `
		SELECT DISTINCT c.id, c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		ORDER BY c.published_date DESC
	`
	rows, err := db.Pool.Query(context.Background(), query, userID)
	if err != nil {
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=cves_export.csv")

	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write([]string{"CVE ID", "Description", "CVSS Score", "CISA KEV", "Published Date"}); err != nil {
		http.Error(w, "Error writing CSV header", http.StatusInternalServerError)
		return
	}

	for rows.Next() {
		var cve models.CVE
		err := rows.Scan(&cve.ID, &cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.CISAKEV, &cve.PublishedDate)
		if err != nil {
			continue
		}
		if err := writer.Write([]string{
			cve.CVEID,
			cve.Description,
			fmt.Sprintf("%.1f", cve.CVSSScore),
			fmt.Sprintf("%t", cve.CISAKEV),
			cve.PublishedDate.Format("2006-01-02"),
		}); err != nil {
			// Stop writing on error
			break
		}
	}
}
