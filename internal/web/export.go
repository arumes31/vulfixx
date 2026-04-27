package web

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (a *App) ExportCVEsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Fetch CVEs filtered by user subscriptions (same as dashboard but all of them)
	query := `
		SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.cisa_kev, c.published_date
		FROM cves c
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		ORDER BY c.published_date DESC
	`
	rows, err := a.Pool.Query(r.Context(), query, userID)
	if err != nil {
		log.Printf("Error fetching CVEs for export: %v", err)
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// 1. Write the header to a temporary buffer first to ensure it's successful
	// before committing response headers.
	var buf bytes.Buffer
	bufWriter := csv.NewWriter(&buf)
	header := []string{"CVE ID", "Description", "CVSS Score", "CISA KEV", "Published Date"}
	if err := bufWriter.Write(header); err != nil {
		log.Printf("Error preparing CSV header: %v", err)
		http.Error(w, "Error preparing export", http.StatusInternalServerError)
		return
	}
	bufWriter.Flush()
	if err := bufWriter.Error(); err != nil {
		log.Printf("Error flushing CSV header: %v", err)
		http.Error(w, "Error preparing export", http.StatusInternalServerError)
		return
	}

	// 2. Set response headers only now that we know we can at least write the header.
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=cves_export.csv")
	// Write the buffered header to the response.
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Printf("Error writing CSV header to response: %v", err)
		return
	}

	// 3. Stream the rest of the rows directly.
	csvWriter := csv.NewWriter(w)
	var skipped int
	var total int
	for rows.Next() {
		var cveID, description string
		var cvssScore float64
		var cisaKEV bool
		var publishedDate time.Time

		if err := rows.Scan(&cveID, &description, &cvssScore, &cisaKEV, &publishedDate); err != nil {
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
