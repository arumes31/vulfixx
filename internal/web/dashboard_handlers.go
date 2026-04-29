package web

import (
	"cve-tracker/internal/models"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

func (a *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	activeTeamID, _ := a.GetActiveTeamID(r)

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
	statusFilter := r.URL.Query().Get("status")
	kevOnly := r.URL.Query().Get("kev") == "true"
	minCvssStr := r.URL.Query().Get("min_cvss")
	maxCvssStr := r.URL.Query().Get("max_cvss")

	minCvss, _ := strconv.ParseFloat(minCvssStr, 64)
	maxCvss, _ := strconv.ParseFloat(maxCvssStr, 64)
	if maxCvss == 0 {
		maxCvss = 10.0
	}

	var totalItems, kevCount, critCount, progressCount int

	args := []any{userID}
	argIdx := 2 // $1 is always userID

	statusJoinCond := "ucs.user_id = $1 AND ucs.team_id IS NULL"
	if activeTeamID > 0 {
		statusJoinCond = fmt.Sprintf("ucs.team_id = $%d", argIdx)
		args = append(args, activeTeamID)
		argIdx++
	}

	metricsQuery := fmt.Sprintf(`
		SELECT
			COUNT(DISTINCT c.id) as total_cves,
			COUNT(DISTINCT CASE WHEN c.cisa_kev = true THEN c.id END) as kev_count,
			COUNT(DISTINCT CASE WHEN c.cvss_score >= 9.0 THEN c.id END) as critical_count,
			COUNT(DISTINCT CASE WHEN ucs.status = 'in_progress' THEN c.id END) as in_progress_count
		FROM cves c
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND %s
	`, statusJoinCond)

	whereClause := " WHERE (1=1) "
	if !searchAll {
		metricsQuery += " INNER JOIN user_subscriptions us ON us.user_id = $1 "
		whereClause += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		whereClause += " AND c.cvss_score >= us.min_severity "
		whereClause += " AND (us.keyword = '' OR c.description ILIKE '%%' || us.keyword || '%%') "
	} else {
		if statusFilter == "" || statusFilter == "active" {
			whereClause += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		} else if statusFilter != "" {
			whereClause += fmt.Sprintf(" AND ucs.status = $%d ", argIdx)
			args = append(args, statusFilter)
			argIdx++
		}
	}

	if searchQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.cve_id ILIKE $%d OR c.description ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%"+searchQuery+"%")
		argIdx++
	}
	if kevOnly {
		whereClause += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		whereClause += fmt.Sprintf(" AND c.cvss_score >= $%d ", argIdx)
		args = append(args, minCvss)
		argIdx++
	}
	if maxCvss < 10 {
		whereClause += fmt.Sprintf(" AND c.cvss_score <= $%d ", argIdx)
		args = append(args, maxCvss)
		argIdx++
	}
	if startDate != "" {
		whereClause += fmt.Sprintf(" AND c.published_date >= $%d ", argIdx)
		args = append(args, startDate)
		argIdx++
	}
	if endDate != "" {
		whereClause += fmt.Sprintf(" AND c.published_date <= $%d ", argIdx)
		args = append(args, endDate)
		argIdx++
	}

	fullMetricsQuery := metricsQuery + whereClause
	err := a.Pool.QueryRow(r.Context(), fullMetricsQuery, args...).Scan(&totalItems, &kevCount, &critCount, &progressCount)
	if err != nil {
		log.Printf("Dashboard metrics error: %v", err)
	}

	notesJoinCond := "ucn.user_id = $1 AND ucn.team_id IS NULL"
	if activeTeamID > 0 {
		// activeTeamID is already in args if it was > 0, find its index
		teamArgIdx := -1
		for i, v := range args {
			if id, ok := v.(int); ok && id == activeTeamID {
				teamArgIdx = i + 1
				break
			}
		}
		if teamArgIdx != -1 {
			notesJoinCond = fmt.Sprintf("ucn.team_id = $%d", teamArgIdx)
		}
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT c.id, c.cve_id, c.description, c.cvss_score, c.vector_string, c.cisa_kev, c.published_date, c.updated_date, COALESCE(ucs.status, 'active') as status, c."references", ucn.notes
		FROM cves c
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND %s
		LEFT JOIN cve_notes ucn ON c.id = ucn.cve_id AND %s
	`, statusJoinCond, notesJoinCond)

	if !searchAll {
		query += " INNER JOIN user_subscriptions us ON us.user_id = $1 "
	}

	query += whereClause
	query += fmt.Sprintf(" ORDER BY c.published_date DESC LIMIT $%d OFFSET $%d ", argIdx, argIdx+1)

	finalArgs := append(args, pageSize, offset)

	rows, err := a.Pool.Query(r.Context(), query, finalArgs...)
	if err != nil {
		log.Printf("Dashboard query error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var notes sql.NullString
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes); err != nil {
			log.Printf("Error scanning dashboard CVE row (CVEID=%s): %v", c.CVEID, err)
			continue
		}
		c.Notes = notes.String
		cves = append(cves, c)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating dashboard CVEs: %v", err)
	}

	threatLevel := "LOW"
	threatColor := "text-blue-400"
	if kevCount > 0 || critCount > 0 {
		threatLevel = "HIGH"
		threatColor = "text-red-500"
	}

	totalPages := (totalItems + pageSize - 1) / pageSize

	// Fetch severity distribution
	var severityCounts struct {
		Critical int
		High     int
		Medium   int
		Low      int
	}

	// Create base query from metricsQuery by replacing its SELECT list
	idx := strings.Index(metricsQuery, "FROM cves c")
	var baseFromJoin string
	if idx >= 0 {
		baseFromJoin = metricsQuery[idx:]
	} else {
		baseFromJoin = " FROM cves c "
	}

	// Severity distribution query arguments
	// Use 'args' which contains parameters for whereClause
	severityQuery := "SELECT " +
		"COUNT(DISTINCT CASE WHEN c.cvss_score >= 9.0 THEN c.id END), " +
		"COUNT(DISTINCT CASE WHEN c.cvss_score >= 7.0 AND c.cvss_score < 9.0 THEN c.id END), " +
		"COUNT(DISTINCT CASE WHEN c.cvss_score >= 4.0 AND c.cvss_score < 7.0 THEN c.id END), " +
		"COUNT(DISTINCT CASE WHEN c.cvss_score < 4.0 THEN c.id END) " +
		baseFromJoin + whereClause

	_ = a.Pool.QueryRow(r.Context(), severityQuery, args...).Scan(&severityCounts.Critical, &severityCounts.High, &severityCounts.Medium, &severityCounts.Low)

	// Fetch status distribution for the current view
	var statusCounts struct {
		Active     int
		InProgress int
		Resolved   int
		Ignored    int
	}
	statusQuery := "SELECT " +
		"COUNT(DISTINCT CASE WHEN COALESCE(ucs.status, 'active') = 'active' THEN c.id END), " +
		"COUNT(DISTINCT CASE WHEN ucs.status = 'in_progress' THEN c.id END), " +
		"COUNT(DISTINCT CASE WHEN ucs.status = 'resolved' THEN c.id END), " +
		"COUNT(DISTINCT CASE WHEN ucs.status = 'ignored' THEN c.id END) " +
		baseFromJoin + whereClause

	_ = a.Pool.QueryRow(r.Context(), statusQuery, args...).Scan(&statusCounts.Active, &statusCounts.InProgress, &statusCounts.Resolved, &statusCounts.Ignored)

	a.RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"CVEs":           cves,
		"Total":          totalItems,
		"KevCount":       kevCount,
		"CritCount":      critCount,
		"ProgressCount":  progressCount,
		"ThreatLevel":    threatLevel,
		"ThreatColor":    threatColor,
		"CurrentPage":    page,
		"TotalPages":     totalPages,
		"HasPrev":        page > 1,
		"HasNext":        page < totalPages,
		"PrevPage":       page - 1,
		"NextPage":       page + 1,
		"Query":          searchQuery,
		"ActiveTeamID":   activeTeamID,
		"SeverityCounts": severityCounts,
		"StatusCounts":   statusCounts,
	})
}

func (a *App) UpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	activeTeamID, _ := a.GetActiveTeamID(r)

	var req struct {
		CVEID  int    `json:"cve_id"`
		Status string `json:"status"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024*10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.SendResponse(w, r, false, "", "", "Bad request")
		return
	}

	allowedStatuses := map[string]bool{"active": true, "in_progress": true, "resolved": true, "ignored": true}
	if !allowedStatuses[req.Status] {
		a.SendResponse(w, r, false, "", "", "Invalid status")
		return
	}

	if activeTeamID > 0 {
		var isMember bool
		err := a.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", activeTeamID, userID).Scan(&isMember)
		if err != nil || !isMember {
			a.SendResponse(w, r, false, "", "", "Forbidden: You are not a member of this team")
			return
		}
	}

	if req.Status == "active" {
		query := "DELETE FROM user_cve_status WHERE cve_id = $1 AND "
		if activeTeamID > 0 {
			query += "team_id = $2"
			_, err := a.Pool.Exec(r.Context(), query, req.CVEID, activeTeamID)
			if err != nil {
				a.SendResponse(w, r, false, "", "", "Internal server error")
				return
			}
		} else {
			query += "user_id = $2 AND team_id IS NULL"
			_, err := a.Pool.Exec(r.Context(), query, req.CVEID, userID)
			if err != nil {
				a.SendResponse(w, r, false, "", "", "Internal server error")
				return
			}
		}
	} else {
		var teamPtr *int
		if activeTeamID > 0 {
			teamPtr = &activeTeamID
		}

		query := `
			INSERT INTO user_cve_status (user_id, team_id, cve_id, status)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, cve_id) WHERE team_id IS NULL DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
		`
		if activeTeamID > 0 {
			query = `
				INSERT INTO user_cve_status (user_id, team_id, cve_id, status)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (team_id, cve_id) WHERE team_id IS NOT NULL DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
			`
		}
		_, err := a.Pool.Exec(r.Context(), query, userID, teamPtr, req.CVEID, req.Status)
		if err != nil {
			log.Printf("UpdateStatus Error: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
	}

	a.LogActivity(r.Context(), userID, "cve_status_updated", fmt.Sprintf("Updated CVE ID %d status to %s", req.CVEID, req.Status), r.RemoteAddr, r.UserAgent())
	a.SendResponse(w, r, true, "Remediation status updated", "", "")
}

func (a *App) UpdateCVENoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	activeTeamID, _ := a.GetActiveTeamID(r)

	var req struct {
		CVEID int    `json:"cve_id"`
		Notes string `json:"notes"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024*100)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.SendResponse(w, r, false, "", "", "Bad request")
		return
	}

	if len(req.Notes) > 10000 {
		a.SendResponse(w, r, false, "", "", "Notes too long (max 10000 characters)")
		return
	}

	if activeTeamID > 0 {
		var isMember bool
		err := a.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", activeTeamID, userID).Scan(&isMember)
		if err != nil || !isMember {
			a.SendResponse(w, r, false, "", "", "Forbidden: You are not a member of this team")
			return
		}
	}

	var teamPtr *int
	if activeTeamID > 0 {
		teamPtr = &activeTeamID
	}

	query := `
		INSERT INTO cve_notes (user_id, team_id, cve_id, notes)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, cve_id) WHERE team_id IS NULL DO UPDATE SET notes = EXCLUDED.notes, updated_at = NOW()
	`
	if activeTeamID > 0 {
		query = `
			INSERT INTO cve_notes (user_id, team_id, cve_id, notes)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (team_id, cve_id) WHERE team_id IS NOT NULL DO UPDATE SET notes = EXCLUDED.notes, updated_at = NOW()
		`
	}

	_, err := a.Pool.Exec(r.Context(), query, userID, teamPtr, req.CVEID, req.Notes)
	if err != nil {
		log.Printf("UpdateNote Error: %v", err)
		a.SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	a.LogActivity(r.Context(), userID, "cve_note_updated", fmt.Sprintf("Updated notes for CVE ID %d", req.CVEID), r.RemoteAddr, r.UserAgent())
	a.SendResponse(w, r, true, "Notes saved successfully", "", "")
}

func (a *App) BulkUpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	activeTeamID, _ := a.GetActiveTeamID(r)

	var req struct {
		CVEIDs []int  `json:"cve_ids"`
		Status string `json:"status"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.SendResponse(w, r, false, "", "", "Bad request")
		return
	}

	allowedStatuses := map[string]bool{"active": true, "in_progress": true, "resolved": true, "ignored": true}
	if !allowedStatuses[req.Status] {
		a.SendResponse(w, r, false, "", "", "Invalid status")
		return
	}

	if len(req.CVEIDs) == 0 {
		a.SendResponse(w, r, true, "No CVEs selected", "", "")
		return
	}

	if len(req.CVEIDs) > 1000 {
		a.SendResponse(w, r, false, "", "", "Too many CVE IDs (max 1000)")
		return
	}

	if activeTeamID > 0 {
		var isMember bool
		err := a.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", activeTeamID, userID).Scan(&isMember)
		if err != nil || !isMember {
			a.SendResponse(w, r, false, "", "", "Forbidden: You are not a member of this team")
			return
		}
	}

	var teamPtr *int
	if activeTeamID > 0 {
		teamPtr = &activeTeamID
	}

	tx, err := a.Pool.Begin(r.Context())
	if err != nil {
		a.SendResponse(w, r, false, "", "", "Internal server error")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var query string
	if req.Status == "active" {
		if activeTeamID > 0 {
			query = "DELETE FROM user_cve_status WHERE cve_id = ANY($1::int[]) AND team_id = $2"
			_, err = tx.Exec(r.Context(), query, req.CVEIDs, activeTeamID)
		} else {
			query = "DELETE FROM user_cve_status WHERE cve_id = ANY($1::int[]) AND user_id = $2 AND team_id IS NULL"
			_, err = tx.Exec(r.Context(), query, req.CVEIDs, userID)
		}
	} else {
		if activeTeamID > 0 {
			query = `
				INSERT INTO user_cve_status (user_id, team_id, cve_id, status)
				SELECT $1, $2, id, $3 FROM unnest($4::int[]) AS id
				ON CONFLICT (team_id, cve_id) WHERE team_id IS NOT NULL DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
			`
		} else {
			query = `
				INSERT INTO user_cve_status (user_id, team_id, cve_id, status)
				SELECT $1, $2, id, $3 FROM unnest($4::int[]) AS id
				ON CONFLICT (user_id, cve_id) WHERE team_id IS NULL DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
			`
		}
		_, err = tx.Exec(r.Context(), query, userID, teamPtr, req.Status, req.CVEIDs)
	}

	if err != nil {
		log.Printf("BulkUpdate Error: %v", err)
		a.SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		a.SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	a.LogActivity(r.Context(), userID, "cve_status_bulk_updated", fmt.Sprintf("Bulk updated %d CVEs to %s", len(req.CVEIDs), req.Status), r.RemoteAddr, r.UserAgent())
	a.SendResponse(w, r, true, fmt.Sprintf("Updated %d CVEs", len(req.CVEIDs)), "", "")
}

func (a *App) PublicDashboardHandler(w http.ResponseWriter, r *http.Request) {
	pageStr := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	if page > 1000 { // Max depth for guest users
		page = 1000
	}
	pageSize := 20
	offset := (page - 1) * pageSize

	searchQuery := r.URL.Query().Get("q")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")
	kevOnly := r.URL.Query().Get("kev") == "true"
	minCvssStr := r.URL.Query().Get("min_cvss")
	maxCvssStr := r.URL.Query().Get("max_cvss")

	minCvss, _ := strconv.ParseFloat(minCvssStr, 64)
	maxCvss, _ := strconv.ParseFloat(maxCvssStr, 64)
	if maxCvss == 0 {
		maxCvss = 10.0
	}

	var totalItems, kevCount, critCount int

	metricsQuery := `
		SELECT
			COUNT(DISTINCT c.id) as total_cves,
			COUNT(DISTINCT CASE WHEN c.cisa_kev = true THEN c.id END) as kev_count,
			COUNT(DISTINCT CASE WHEN c.cvss_score >= 9.0 THEN c.id END) as critical_count
		FROM cves c
	`

	whereClause := " WHERE (1=1) "
	args := []any{}
	argIdx := 1

	if searchQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.cve_id ILIKE $%d OR c.description ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%"+searchQuery+"%")
		argIdx++
	}

	if kevOnly {
		whereClause += " AND c.cisa_kev = true "
	}

	if minCvss > 0 {
		whereClause += fmt.Sprintf(" AND c.cvss_score >= $%d ", argIdx)
		args = append(args, minCvss)
		argIdx++
	}
	if maxCvss < 10 {
		whereClause += fmt.Sprintf(" AND c.cvss_score <= $%d ", argIdx)
		args = append(args, maxCvss)
		argIdx++
	}
	if startDate != "" {
		whereClause += fmt.Sprintf(" AND c.published_date >= $%d ", argIdx)
		args = append(args, startDate)
		argIdx++
	}
	if endDate != "" {
		whereClause += fmt.Sprintf(" AND c.published_date <= $%d ", argIdx)
		args = append(args, endDate)
		argIdx++
	}

	fullMetricsQuery := metricsQuery + whereClause
	err := a.Pool.QueryRow(r.Context(), fullMetricsQuery, args...).Scan(&totalItems, &kevCount, &critCount)
	if err != nil {
		log.Printf("Public dashboard metrics error: %v", err)
	}

	query := `
		SELECT 
			c.id, c.cve_id, c.description, c.cvss_score, vector_string, c.cisa_kev, 
			c.published_date, c.updated_date, 'active' as status, c.references, '' as notes
		FROM cves c
	`
	query += whereClause
	query += fmt.Sprintf(" ORDER BY c.published_date DESC LIMIT $%d OFFSET $%d ", argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := a.Pool.Query(r.Context(), query, args...)
	if err != nil {
		log.Printf("Public dashboard query error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var notes sql.NullString
		err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes)
		if err != nil {
			log.Printf("Error scanning public CVE: %v", err)
			continue
		}
		c.Notes = notes.String
		cves = append(cves, c)
	}

	threatLevel := "LOW"
	threatColor := "text-blue-400"
	if kevCount > 0 || critCount > 0 {
		threatLevel = "HIGH"
		threatColor = "text-red-500"
	}

	totalPages := (totalItems + pageSize - 1) / pageSize

	var severityCounts struct {
		Critical int
		High     int
		Medium   int
		Low      int
	}
	_ = a.Pool.QueryRow(r.Context(), `
		SELECT 
			COUNT(*) FILTER (WHERE cvss_score >= 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 7.0 AND cvss_score < 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 4.0 AND cvss_score < 7.0),
			COUNT(*) FILTER (WHERE cvss_score < 4.0)
		FROM cves
	`).Scan(&severityCounts.Critical, &severityCounts.High, &severityCounts.Medium, &severityCounts.Low)

	a.RenderTemplate(w, r, "public_dashboard.html", map[string]interface{}{
		"CVEs":            cves,
		"Total":           totalItems,
		"KevCount":        kevCount,
		"CritCount":       critCount,
		"ThreatLevel":     threatLevel,
		"ThreatColor":     threatColor,
		"Page":            page,
		"TotalPages":      totalPages,
		"Query":           searchQuery,
		"StartDate":       startDate,
		"EndDate":         endDate,
		"KevOnly":         kevOnly,
		"MinCvss":         minCvss,
		"MaxCvss":         maxCvss,
		"SeverityCounts":  severityCounts,
		"MetaTitle":       "Vulfixx - Public CVE Tracker & Threat Intelligence",
		"MetaDescription": "Monitor real-time vulnerability data, CISA KEV listings, and critical security advisories. The ultimate tracker for security professionals.",
		"Trending":        a.getTrendingCVEs(r),
	})
}

func (a *App) getTrendingCVEs(r *http.Request) []models.CVE {
	rows, err := a.Pool.Query(r.Context(), `
		SELECT 
			id, cve_id, description, cvss_score, vector_string, cisa_kev, 
			published_date, updated_date, 'active' as status, references, '' as notes
		FROM cves 
		WHERE cisa_kev = true OR cvss_score >= 9.5
		ORDER BY published_date DESC LIMIT 4
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var notes sql.NullString
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes); err != nil {
			log.Printf("Error scanning trending CVE: %v", err)
			continue
		}
		cves = append(cves, c)
	}
	return cves
}

func (a *App) CVEDetailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cveID := vars["id"]

	var c models.CVE
	err := a.Pool.QueryRow(r.Context(), `
		SELECT 
			id, cve_id, description, cvss_score, vector_string, cisa_kev, 
			published_date, updated_date, 'active' as status, references, 
			epss_score, cwe_id, cwe_name, github_poc_count
		FROM cves 
		WHERE cve_id = $1
	`, cveID).Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			log.Printf("CVEDetailHandler error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Generate JSON-LD safely
	jsonLD := map[string]interface{}{
		"@context":    "https://schema.org",
		"@type":       "WebPage",
		"name":        fmt.Sprintf("%s Vulnerability Details", c.CVEID),
		"description": c.Description,
		"mainEntity": map[string]interface{}{
			"@type":         "CreativeWork",
			"name":          c.CVEID,
			"description":   c.Description,
			"datePublished": c.PublishedDate.Format("2006-01-02"),
			"dateModified":  c.UpdatedDate.Format("2006-01-02"),
			"author": map[string]interface{}{
				"@type": "Organization",
				"name":  "Vulfixx Threat Intelligence",
			},
		},
	}
	jsonLDBytes, _ := json.Marshal(jsonLD)
	// Prevent </script> injection: escape the forward slash so the script tag can't be closed.
	safeJSONLD := strings.ReplaceAll(string(jsonLDBytes), "</", `<\/`)

	a.RenderTemplate(w, r, "cve_detail.html", map[string]interface{}{
		"CVE":             c,
		"MetaTitle":       fmt.Sprintf("%s - %s | Vulfixx Threat Intel", c.CVEID, c.Description),
		"MetaDescription": fmt.Sprintf("Security analysis of %s. Severity: %.1f. %s", c.CVEID, c.CVSSScore, c.Description),
		"Canonical":       fmt.Sprintf("/cve/%s", c.CVEID),
		/* #nosec G203 */
		"JSONLD": template.JS(safeJSONLD), // safe: JSON-marshaled then </script>-escaped
	})
}
