package web

import (
	"cve-tracker/internal/db"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"time"
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
	rows, err := db.Pool.Query(r.Context(), query, userID)
	if err != nil {
		log.Printf("Error fetching CVEs for export: %v", err)
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Set response headers before writing body (streaming)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=cves_export.csv")

	csvWriter := csv.NewWriter(w)
	header := []string{"CVE ID", "Description", "CVSS Score", "CISA KEV", "Published Date"}
	if err := csvWriter.Write(header); err != nil {
		log.Printf("Error writing CSV header: %v", err)
		return
	}

	var skipped int
	var total int
	for rows.Next() {
		var id int
		var cveID, description string
		var cvssScore float64
		var cisaKEV bool
		var publishedDate time.Time

		if err := rows.Scan(&id, &cveID, &description, &cvssScore, &cisaKEV, &publishedDate); err != nil {
			skipped++
			log.Printf("Warning: skipping row during CVE export (scan error): %v", err)
			continue
		}
		total++
		row := []string{
			cveID,
			description,
			fmt.Sprintf("%.1f", cvssScore),
			fmt.Sprintf("%t", cisaKEV),
			publishedDate.Format("2006-01-02"),
		}
		if err := csvWriter.Write(row); err != nil {
			log.Printf("Error writing CSV row for %s: %v", cveID, err)
			return
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating CVE export rows: %v", err)
	}

	if skipped > 0 {
		log.Printf("CVE export: %d row(s) skipped due to scan errors, %d row(s) exported", skipped, total)
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		log.Printf("CSV writer flush error: %v", err)
	}
}
