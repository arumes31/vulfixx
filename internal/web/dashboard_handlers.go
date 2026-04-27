package web

import (
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	activeTeamID, _ := GetActiveTeamID(r)

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

	statusJoinCond := "ucs.user_id = $1 AND ucs.team_id IS NULL"
	if activeTeamID > 0 {
		statusJoinCond = "ucs.team_id = $8"
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
		} else {
			whereClause += " AND ucs.status = $7 "
		}
	}

	whereClause += " AND ($2 = '' OR c.cve_id ILIKE '%%' || $2 || '%%' OR c.description ILIKE '%%' || $2 || '%%') "
	if kevOnly {
		whereClause += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		whereClause += " AND c.cvss_score >= $9 "
	}
	if maxCvss < 10 {
		whereClause += " AND c.cvss_score <= $10 "
	}
	if startDate != "" {
		whereClause += " AND c.published_date >= $3 "
	}
	if endDate != "" {
		whereClause += " AND c.published_date <= $4 "
	}

	fullMetricsQuery := metricsQuery + whereClause
	err := db.Pool.QueryRow(r.Context(), fullMetricsQuery, userID, searchQuery, startDate, endDate, pageSize, offset, statusFilter, activeTeamID, minCvss, maxCvss).Scan(&totalItems, &kevCount, &critCount, &progressCount)
	if err != nil {
		log.Printf("Dashboard metrics error: %v", err)
	}

	notesJoinCond := "ucn.user_id = $1 AND ucn.team_id IS NULL"
	if activeTeamID > 0 {
		notesJoinCond = "ucn.team_id = $8"
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
	query += " ORDER BY c.published_date DESC LIMIT $5 OFFSET $6 "

	rows, err := db.Pool.Query(r.Context(), query, userID, searchQuery, startDate, endDate, pageSize, offset, statusFilter, activeTeamID, minCvss, maxCvss)
	if err != nil {
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
	_ = db.Pool.QueryRow(r.Context(), `
		SELECT 
			COUNT(*) FILTER (WHERE cvss_score >= 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 7.0 AND cvss_score < 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 4.0 AND cvss_score < 7.0),
			COUNT(*) FILTER (WHERE cvss_score < 4.0)
		FROM cves
	`).Scan(&severityCounts.Critical, &severityCounts.High, &severityCounts.Medium, &severityCounts.Low)

	// Fetch status distribution for the current view
	var statusCounts struct {
		Active     int
		InProgress int
		Resolved   int
		Ignored    int
	}
	statusQuery := fmt.Sprintf(`
		SELECT 
			COUNT(*) FILTER (WHERE COALESCE(ucs.status, 'active') = 'active'),
			COUNT(*) FILTER (WHERE ucs.status = 'in_progress'),
			COUNT(*) FILTER (WHERE ucs.status = 'resolved'),
			COUNT(*) FILTER (WHERE ucs.status = 'ignored')
		FROM cves c
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND %s
	`, statusJoinCond)
	_ = db.Pool.QueryRow(r.Context(), statusQuery, userID, searchQuery, startDate, endDate, pageSize, offset, statusFilter, activeTeamID, minCvss, maxCvss).Scan(&statusCounts.Active, &statusCounts.InProgress, &statusCounts.Resolved, &statusCounts.Ignored)

	RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
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

func UpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	activeTeamID, _ := GetActiveTeamID(r)

	var req struct {
		CVEID  int    `json:"cve_id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendResponse(w, r, false, "", "", "Bad request")
		return
	}

	allowedStatuses := map[string]bool{"active": true, "in_progress": true, "resolved": true, "ignored": true}
	if !allowedStatuses[req.Status] {
		SendResponse(w, r, false, "", "", "Invalid status")
		return
	}

	if activeTeamID > 0 {
		var isMember bool
		err := db.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", activeTeamID, userID).Scan(&isMember)
		if err != nil || !isMember {
			SendResponse(w, r, false, "", "", "Forbidden: You are not a member of this team")
			return
		}
	}

	if req.Status == "active" {
		query := "DELETE FROM user_cve_status WHERE cve_id = $1 AND "
		if activeTeamID > 0 {
			query += "team_id = $2"
			_, err := db.Pool.Exec(r.Context(), query, req.CVEID, activeTeamID)
			if err != nil {
				SendResponse(w, r, false, "", "", "Internal server error")
				return
			}
		} else {
			query += "user_id = $2 AND team_id IS NULL"
			_, err := db.Pool.Exec(r.Context(), query, req.CVEID, userID)
			if err != nil {
				SendResponse(w, r, false, "", "", "Internal server error")
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
		_, err := db.Pool.Exec(r.Context(), query, userID, teamPtr, req.CVEID, req.Status)
		if err != nil {
			log.Printf("UpdateStatus Error: %v", err)
			SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
	}

	LogActivity(r.Context(), userID, "cve_status_updated", fmt.Sprintf("Updated CVE ID %d status to %s", req.CVEID, req.Status), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Remediation status updated", "", "")
}

func UpdateCVENoteHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	activeTeamID, _ := GetActiveTeamID(r)

	var req struct {
		CVEID int    `json:"cve_id"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendResponse(w, r, false, "", "", "Bad request")
		return
	}

	if len(req.Notes) > 10000 {
		SendResponse(w, r, false, "", "", "Notes too long (max 10000 characters)")
		return
	}

	if activeTeamID > 0 {
		var isMember bool
		err := db.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", activeTeamID, userID).Scan(&isMember)
		if err != nil || !isMember {
			SendResponse(w, r, false, "", "", "Forbidden: You are not a member of this team")
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

	_, err := db.Pool.Exec(r.Context(), query, userID, teamPtr, req.CVEID, req.Notes)
	if err != nil {
		log.Printf("UpdateNote Error: %v", err)
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	LogActivity(r.Context(), userID, "cve_note_updated", fmt.Sprintf("Updated notes for CVE ID %d", req.CVEID), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Notes saved successfully", "", "")
}

func BulkUpdateCVEStatusHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	activeTeamID, _ := GetActiveTeamID(r)

	var req struct {
		CVEIDs []int  `json:"cve_ids"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendResponse(w, r, false, "", "", "Bad request")
		return
	}

	allowedStatuses := map[string]bool{"active": true, "in_progress": true, "resolved": true, "ignored": true}
	if !allowedStatuses[req.Status] {
		SendResponse(w, r, false, "", "", "Invalid status")
		return
	}

	if len(req.CVEIDs) == 0 {
		SendResponse(w, r, true, "No CVEs selected", "", "")
		return
	}

	if len(req.CVEIDs) > 1000 {
		SendResponse(w, r, false, "", "", "Too many CVE IDs (max 1000)")
		return
	}

	if activeTeamID > 0 {
		var isMember bool
		err := db.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", activeTeamID, userID).Scan(&isMember)
		if err != nil || !isMember {
			SendResponse(w, r, false, "", "", "Forbidden: You are not a member of this team")
			return
		}
	}

	var teamPtr *int
	if activeTeamID > 0 {
		teamPtr = &activeTeamID
	}

	tx, err := db.Pool.Begin(r.Context())
	if err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
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
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	LogActivity(r.Context(), userID, "cve_status_bulk_updated", fmt.Sprintf("Bulk updated %d CVEs to %s", len(req.CVEIDs), req.Status), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, fmt.Sprintf("Updated %d CVEs", len(req.CVEIDs)), "", "")
}

func PublicDashboardHandler(w http.ResponseWriter, r *http.Request) {
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
	
	// Arguments for public view: $1=search, $2=start, $3=end, $4=min, $5=max
	whereClause += " AND ($1 = '' OR c.cve_id ILIKE '%%' || $1 || '%%' OR c.description ILIKE '%%' || $1 || '%%') "
	if kevOnly {
		whereClause += " AND c.cisa_kev = true "
	}
	if minCvss > 0 {
		whereClause += " AND c.cvss_score >= $4 "
	}
	if maxCvss < 10 {
		whereClause += " AND c.cvss_score <= $5 "
	}
	if startDate != "" {
		whereClause += " AND c.published_date >= $2 "
	}
	if endDate != "" {
		whereClause += " AND c.published_date <= $3 "
	}

	fullMetricsQuery := metricsQuery + whereClause
	err := db.Pool.QueryRow(r.Context(), fullMetricsQuery, searchQuery, startDate, endDate, minCvss, maxCvss).Scan(&totalItems, &kevCount, &critCount)
	if err != nil {
		log.Printf("Public dashboard metrics error: %v", err)
	}

	query := `
		SELECT 
			c.id, c.cve_id, c.description, c.cvss_score, c.cvss_vector, c.cisa_kev, 
			c.published_date, c.updated_date, 'active' as status, c.references, '' as notes
		FROM cves c
	`
	query += whereClause
	query += " ORDER BY c.published_date DESC LIMIT $6 OFFSET $7 "

	// Final args: 1-5 same, $6=pageSize, $7=offset
	rows, err := db.Pool.Query(r.Context(), query, searchQuery, startDate, endDate, minCvss, maxCvss, pageSize, offset)
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
	_ = db.Pool.QueryRow(r.Context(), `
		SELECT 
			COUNT(*) FILTER (WHERE cvss_score >= 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 7.0 AND cvss_score < 9.0),
			COUNT(*) FILTER (WHERE cvss_score >= 4.0 AND cvss_score < 7.0),
			COUNT(*) FILTER (WHERE cvss_score < 4.0)
		FROM cves
	`).Scan(&severityCounts.Critical, &severityCounts.High, &severityCounts.Medium, &severityCounts.Low)

	RenderTemplate(w, r, "public_dashboard.html", map[string]interface{}{
		"CVEs":           cves,
		"Total":          totalItems,
		"KevCount":       kevCount,
		"CritCount":      critCount,
		"ThreatLevel":    threatLevel,
		"ThreatColor":    threatColor,
		"Page":           page,
		"TotalPages":     totalPages,
		"Query":          searchQuery,
		"StartDate":      startDate,
		"EndDate":        endDate,
		"KevOnly":        kevOnly,
		"MinCvss":        minCvss,
		"MaxCvss":        maxCvss,
		"SeverityCounts": severityCounts,
		"MetaTitle":      "Vulfixx - Public CVE Tracker & Threat Intelligence",
		"MetaDescription": "Monitor real-time vulnerability data, CISA KEV listings, and critical security advisories. The ultimate tracker for security professionals.",
		"Trending":       getTrendingCVEs(r),
	})
}

func getTrendingCVEs(r *http.Request) []models.CVE {
	rows, err := db.Pool.Query(r.Context(), `
		SELECT 
			id, cve_id, description, cvss_score, cvss_vector, cisa_kev, 
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
		_ = rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes)
		cves = append(cves, c)
	}
	return cves
}

func CVEDetailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cveID := vars["id"]

	var c models.CVE
	err := db.Pool.QueryRow(r.Context(), `
		SELECT 
			id, cve_id, description, cvss_score, cvss_vector, cisa_kev, 
			published_date, updated_date, 'active' as status, references, 
			epss_score, cwe_id, cwe_name, github_poc_count
		FROM cves 
		WHERE cve_id = $1
	`, cveID).Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount)

	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			log.Printf("CVEDetailHandler error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Generate JSON-LD safely
	jsonLD := map[string]interface{}{
		"@context": "https://schema.org",
		"@type":    "WebPage",
		"name":     fmt.Sprintf("%s Vulnerability Details", c.CVEID),
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

	RenderTemplate(w, r, "cve_detail.html", map[string]interface{}{
		"CVE":             c,
		"MetaTitle":       fmt.Sprintf("%s - %s | Vulfixx Threat Intel", c.CVEID, c.Description),
		"MetaDescription": fmt.Sprintf("Security analysis of %s. Severity: %.1f. %s", c.CVEID, c.CVSSScore, c.Description),
		"Canonical":       fmt.Sprintf("/cve/%s", c.CVEID),
		"JSONLD":          template.HTML(jsonLDBytes), // #nosec G203 -- JSON pre-marshaled and safe
	})
}
