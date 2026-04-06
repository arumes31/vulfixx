package web

import (
	"bytes"
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
)

func ExportCVEsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Fetch CVEs filtered by user subscriptions (same as dashboard but all of them)
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
		log.Printf("Error fetching CVEs for export: %v", err)
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Write CSV to a buffer first to catch errors before sending headers
	var buf bytes.Buffer
	csvWriter := csv.NewWriter(&buf)
	header := []string{"CVE ID", "Description", "CVSS Score", "CISA KEV", "Published Date"}
	if err := csvWriter.Write(header); err != nil {
		log.Printf("Error writing CSV header: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	var cves []models.CVE
	var skipped int
	for rows.Next() {
		var cve models.CVE
		if err := rows.Scan(&cve.ID, &cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.CISAKEV, &cve.PublishedDate); err != nil {
			skipped++
			log.Printf("Warning: skipping row during CVE export (scan error): %v", err)
			continue
		}
		cves = append(cves, cve)
	}
	if skipped > 0 {
		log.Printf("CVE export: %d row(s) skipped due to scan errors, %d row(s) exported", skipped, len(cves))
	}

	for _, cve := range cves {
		row := []string{
			cve.CVEID,
			cve.Description,
			fmt.Sprintf("%.1f", cve.CVSSScore),
			fmt.Sprintf("%t", cve.CISAKEV),
			cve.PublishedDate.Format("2006-01-02"),
		}
		if err := csvWriter.Write(row); err != nil {
			log.Printf("Error writing CSV row: %v", err)
			continue
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		log.Printf("CSV writer error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=cves_export.csv")
	_, _ = w.Write(buf.Bytes())
}
