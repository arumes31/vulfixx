package web

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	pageStr := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	pageSize := 20
	offset := (page - 1) * pageSize

	searchQuery := r.URL.Query().Get("q")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")
	searchAll := r.URL.Query().Get("all") == "true"
	statusFilter := r.URL.Query().Get("status") // e.g. 'active', 'in_progress', 'resolved'
	kevOnly := r.URL.Query().Get("kev") == "true"
	minCvssStr := r.URL.Query().Get("min_cvss")
	maxCvssStr := r.URL.Query().Get("max_cvss")

	minCvss, _ := strconv.ParseFloat(minCvssStr, 64)
	maxCvss, _ := strconv.ParseFloat(maxCvssStr, 64)
	if maxCvss == 0 {
		maxCvss = 10.0
	}

	var totalItems, kevCount int

	metricsQuery := `
		SELECT
			COUNT(DISTINCT c.id) as total_cves,
			COUNT(DISTINCT CASE WHEN c.cisa_kev = true THEN c.id END) as kev_count,
			COUNT(DISTINCT CASE WHEN c.cvss_score >= 9.0 THEN c.id END) as critical_count,
			COUNT(DISTINCT CASE WHEN ucs.status = 'in_progress' THEN c.id END) as in_progress_count
		FROM cves c
	`

	if !searchAll {
		metricsQuery += `
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		`
	} else {
		metricsQuery += `
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (1=1)
		`
		allowedStatuses := map[string]bool{
			"active":        true,
			"in_progress":   true,
			"waiting_patch": true,
			"resolved":      true,
			"ignored":       true,
		}

		if statusFilter == "" || statusFilter == "active" {
			metricsQuery += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		} else if allowedStatuses[statusFilter] {
			metricsQuery += " AND ucs.status = $10 " // Placeholder for statusFilter
		}
	}

	metricsQuery += `
		  AND ($2 = '' OR c.cve_id ILIKE '%' || $2 || '%' OR c.description ILIKE '%' || $2 || '%')
	`
	if kevOnly {
		metricsQuery += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		metricsQuery += fmt.Sprintf(" AND c.cvss_score >= %f ", minCvss)
	}
	if maxCvss < 10 {
		metricsQuery += fmt.Sprintf(" AND c.cvss_score <= %f ", maxCvss)
	}

	args := []interface{}{userID, searchQuery}

	if startDate != "" {
		metricsQuery += ` AND c.published_date >= $3`
		args = append(args, startDate)
	} else {
		metricsQuery += ` AND (1=1 OR $3 = '')`
		args = append(args, "")
	}

	if endDate != "" {
		metricsQuery += ` AND c.published_date <= $4`
		args = append(args, endDate)
	} else {
		metricsQuery += ` AND (1=1 OR $4 = '')`
		args = append(args, "")
	}

	// For the status filter placeholder if it was added
	if strings.Contains(metricsQuery, "$10") {
		args = append(args, statusFilter)
	} else {
		// Padding to keep args aligned if we ever add more positional params
		args = append(args, "")
	}

	var critCount, progressCount int
	err := db.Pool.QueryRow(context.Background(), metricsQuery, args...).Scan(&totalItems, &kevCount, &critCount, &progressCount)
	if err != nil {
		log.Printf("Error counting metrics: %v", err)
	}

	query := `
		SELECT DISTINCT c.id, c.cve_id, c.description, c.cvss_score, c.vector_string, c.cisa_kev, c.published_date, c.updated_date, COALESCE(ucs.status, 'active') as status, c."references", ucn.notes
		FROM cves c
		LEFT JOIN user_cve_notes ucn ON c.id = ucn.cve_id AND ucn.user_id = $1
	`

	if !searchAll {
		query += `
		INNER JOIN user_subscriptions us ON us.user_id = $1
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored'))
		  AND c.cvss_score >= us.min_severity
		  AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%')
		`
	} else {
		query += `
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (1=1)
		`
		if statusFilter == "" || statusFilter == "active" {
			query += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		} else {
			// Reuse the allowlist check from above
			allowedStatuses := map[string]bool{"active":true,"in_progress":true,"waiting_patch":true,"resolved":true,"ignored":true}
			if allowedStatuses[statusFilter] {
				query += " AND ucs.status = $10 "
			}
		}
	}

	query += `
		  AND ($2 = '' OR c.cve_id ILIKE '%' || $2 || '%' OR c.description ILIKE '%' || $2 || '%')
	`
	if kevOnly {
		query += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		query += fmt.Sprintf(" AND c.cvss_score >= %f ", minCvss)
	}
	if maxCvss < 10 {
		query += fmt.Sprintf(" AND c.cvss_score <= %f ", maxCvss)
	}

	if startDate != "" {
		query += ` AND c.published_date >= $3`
	} else {
		query += ` AND (1=1 OR $3 = '')`
	}

	if endDate != "" {
		query += ` AND c.published_date <= $4`
	} else {
		query += ` AND (1=1 OR $4 = '')`
	}

	query += ` ORDER BY c.published_date DESC LIMIT $5 OFFSET $6`

	// Ensure args matches placeholders $1..$6 + $10
	// args is [userID, searchQuery, startDate, endDate]
	// and we added pageSize, offset
	args = append(args, pageSize, offset)
	// If $10 is used, ensure it's at index 9 (10th element)
	if strings.Contains(query, "$10") {
		for len(args) < 9 {
			args = append(args, "")
		}
		args = append(args, statusFilter)
	}

	rows, err := db.Pool.Query(context.Background(), query, args...)
	if err != nil {
		log.Printf("Error fetching CVEs: %v", err)
		http.Error(w, "Error fetching CVEs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var notes sql.NullString
		err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes)
		if err != nil {
			log.Printf("Error scanning CVE: %v", err)
			continue
		}
		c.Notes = notes.String
		cves = append(cves, c)
	}

	// Threat Level Calculation
	threatLevel := "LOW"
	threatColor := "text-primary"
	if kevCount > 5 || critCount > 10 {
		threatLevel = "CRITICAL"
		threatColor = "text-error"
	} else if kevCount > 0 || critCount > 0 {
		threatLevel = "HIGH"
		threatColor = "text-error"
	} else if progressCount > 0 {
		threatLevel = "ELEVATED"
		threatColor = "text-tertiary"
	}
	// Severity Distribution - Calculate across entire dataset (Issue 3)
	severityDist := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	distQuery := `
		SELECT c.cvss_score 
		FROM cves c 
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND ucs.user_id = $1
		WHERE (1=1)
	`
	distArgs := []interface{}{userID}
	if !searchAll {
		distQuery += ` AND EXISTS (SELECT 1 FROM user_subscriptions us WHERE us.user_id = $1 AND (us.keyword = '' OR c.description ILIKE '%' || us.keyword || '%') AND c.cvss_score >= us.min_severity)`
	} else if statusFilter == "" || statusFilter == "active" {
		distQuery += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
	} else {
		allowedStatuses := map[string]bool{"active":true,"in_progress":true,"waiting_patch":true,"resolved":true,"ignored":true}
		if allowedStatuses[statusFilter] {
			distQuery += " AND ucs.status = $2 "
			distArgs = append(distArgs, statusFilter)
		}
	}

	distRows, err := db.Pool.Query(context.Background(), distQuery, distArgs...)
	if err == nil {
		defer distRows.Close()
		for distRows.Next() {
			var score float64
			if err := distRows.Scan(&score); err == nil {
				if score >= 9.0 {
					severityDist["Critical"]++
				} else if score >= 7.0 {
					severityDist["High"]++
				} else if score >= 4.0 {
					severityDist["Medium"]++
				} else {
					severityDist["Low"]++
				}
			}
		}
	} else {
		log.Printf("Dashboard: distribution query failed: %v", err)
	}

	totalPages := (totalItems + pageSize - 1) / pageSize

	RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"CVEs":          cves,
		"Total":         totalItems,
		"KevCount":      kevCount,
		"CritCount":     critCount,
		"ProgressCount": progressCount,
		"ThreatLevel":   threatLevel,
		"ThreatColor":   threatColor,
		"SeverityDist":  severityDist,
		"CurrentPage":   page,
		"TotalPages":    totalPages,
		"HasPrev":       page > 1,
		"HasNext":       page < totalPages,
		"PrevPage":      page - 1,
		"NextPage":      page + 1,
		"Query":         searchQuery,
		"StartDate":     startDate,
		"EndDate":       endDate,
		"SearchAll":     searchAll,
		"StatusFilter":  statusFilter,
		"KevOnly":       kevOnly,
		"MinCvss":       minCvssStr,
		"MaxCvss":       maxCvssStr,
	})
}

func UpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CVEID  int    `json:"cve_id"`
		Status string `json:"status"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	validStatuses := map[string]bool{
		"active":         true,
		"in_progress":    true,
		"waiting_patch":  true,
		"resolved":       true,
		"ignored":        true,
	}
	if !validStatuses[req.Status] {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	if req.Status == "active" {
		_, err = db.Pool.Exec(context.Background(), `
			DELETE FROM user_cve_status WHERE user_id = $1 AND cve_id = $2
		`, userID, req.CVEID)
	} else {
		_, err = db.Pool.Exec(context.Background(), `
			INSERT INTO user_cve_status (user_id, cve_id, status)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, cve_id) DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
		`, userID, req.CVEID, req.Status)
	}

	if err != nil {
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	LogActivity(context.Background(), userID, "remediation", fmt.Sprintf("Updated CVE ID %d status to: %s", req.CVEID, req.Status), r.RemoteAddr, r.UserAgent())

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"success":true}`))
}

func BulkUpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CVEIDs []int  `json:"cve_ids"`
		Status string `json:"status"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Status != "resolved" && req.Status != "ignored" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	if len(req.CVEIDs) == 0 {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
		return
	}

	// Use a transaction for bulk update
	tx, err := db.Pool.Begin(context.Background())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	for _, id := range req.CVEIDs {
		_, err = tx.Exec(context.Background(), `
			INSERT INTO user_cve_status (user_id, cve_id, status)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id, cve_id) DO UPDATE SET status = $3, updated_at = CURRENT_TIMESTAMP
		`, userID, id, req.Status)
		if err != nil {
			http.Error(w, "Failed to update status", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(context.Background()); err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"success":true}`))
}

func UpdateCVENoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CVEID int    `json:"cve_id"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.Pool.Exec(r.Context(), `
		INSERT INTO user_cve_notes (user_id, cve_id, notes, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, cve_id) DO UPDATE SET
			notes = EXCLUDED.notes,
			updated_at = NOW()
	`, userID, req.CVEID, req.Notes)
	if err != nil {
		log.Printf("Error updating note: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
