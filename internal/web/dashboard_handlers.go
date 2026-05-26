package web

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/jackc/pgx/v5"
)

type dashboardFilters struct {
	userID       int
	activeTeamID int
	page         int
	pageSize     int
	offset       int
	searchQuery  string
	startDate    string
	endDate      string
	searchAll    bool
	statusFilter string
	kevOnly      bool
	minCvss      float64
	maxCvss      float64
}

type dashboardMetrics struct {
	Total      int
	Kev        int
	Critical   int
	InProgress int
	SevCrit    int
	SevHigh    int
	SevMed     int
	SevLow     int
	StatActive int
	StatProg   int
	StatRes    int
	StatIgn    int
}

func (a *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	activeTeamID, _ := a.GetActiveTeamID(r)
	filters := a.parseDashboardFilters(r, userID, activeTeamID)
	whereClause, args, argIdx, statusJoinCond, teamArgIdx := a.buildDashboardWhereClause(filters)

	metrics := a.fetchDashboardMetrics(r.Context(), filters, statusJoinCond, whereClause, args)
	cves := a.fetchDashboardCVEs(r.Context(), filters, statusJoinCond, teamArgIdx, whereClause, args, argIdx)
	topCWEs := a.fetchTopCWEs(r.Context(), statusJoinCond, whereClause, args)

	threatLevel := "LOW"
	threatColor := "text-blue-400"
	if metrics.Kev > 0 || metrics.Critical > 0 {
		threatLevel = "HIGH"
		threatColor = "text-red-500"
	}

	totalPages := (metrics.Total + filters.pageSize - 1) / filters.pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	a.RenderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"CVEs":          cves,
		"Total":         metrics.Total,
		"KevCount":      metrics.Kev,
		"CritCount":     metrics.Critical,
		"ProgressCount": metrics.InProgress,
		"ThreatLevel":   threatLevel,
		"ThreatColor":   threatColor,
		"CurrentPage":   filters.page,
		"TotalPages":    totalPages,
		"HasPrev":       filters.page > 1,
		"HasNext":       filters.page < totalPages,
		"PrevPage":      filters.page - 1,
		"NextPage":      filters.page + 1,
		"Query":         filters.searchQuery,
		"ActiveTeamID":  activeTeamID,
		"SeverityCounts": SeverityCounts{
			Critical: metrics.SevCrit,
			High:     metrics.SevHigh,
			Medium:   metrics.SevMed,
			Low:      metrics.SevLow,
		},
		"StatusCounts": StatusCounts{
			Active:     metrics.StatActive,
			InProgress: metrics.StatProg,
			Resolved:   metrics.StatRes,
			Ignored:    metrics.StatIgn,
		},
		"TopCWEs":   topCWEs,
		"csrfToken": csrf.Token(r),
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
		CVEID   int    `json:"cve_id"`
		Status  string `json:"status"`
		Version int    `json:"version"`
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

	if req.Version > 0 {
		res, err := a.Pool.Exec(r.Context(), "UPDATE cves SET version = version + 1 WHERE id = $1 AND version = $2", req.CVEID, req.Version)
		if err != nil {
			log.Printf("Optimistic Lock Exec Error: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
		if res.RowsAffected() == 0 {
			a.SendResponse(w, r, false, "", "", "Conflict: CVE has been modified by another analyst")
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

	a.LogActivity(r.Context(), userID, "cve_status_updated", fmt.Sprintf("Updated CVE ID %d status to %s", req.CVEID, req.Status), a.GetClientIP(r), r.UserAgent())
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
		CVEID   int    `json:"cve_id"`
		Notes   string `json:"notes"`
		Version int    `json:"version"`
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

	if req.Version > 0 {
		res, err := a.Pool.Exec(r.Context(), "UPDATE cves SET version = version + 1 WHERE id = $1 AND version = $2", req.CVEID, req.Version)
		if err != nil {
			log.Printf("Optimistic Lock Exec Error: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
		if res.RowsAffected() == 0 {
			a.SendResponse(w, r, false, "", "", "Conflict: CVE has been modified by another analyst")
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

	a.LogActivity(r.Context(), userID, "cve_note_updated", fmt.Sprintf("Updated notes for CVE ID %d", req.CVEID), a.GetClientIP(r), r.UserAgent())
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

	a.LogActivity(r.Context(), userID, "cve_status_bulk_updated", fmt.Sprintf("Bulk updated %d CVEs to %s", len(req.CVEIDs), req.Status), a.GetClientIP(r), r.UserAgent())
	a.SendResponse(w, r, true, fmt.Sprintf("Updated %d CVEs", len(req.CVEIDs)), "", "")
}

type StatusCounts struct {
	Active     int `json:"active"`
	InProgress int `json:"in_progress"`
	Resolved   int `json:"resolved"`
	Ignored    int `json:"ignored"`
}

type PublicDashboardData struct {
	CVEs            []models.CVE   `json:"cves"`
	Total           int            `json:"total"`
	KevCount        int            `json:"kev_count"`
	CritCount       int            `json:"crit_count"`
	ThreatLevel     string         `json:"threat_level"`
	ThreatColor     string         `json:"threat_color"`
	Page            int            `json:"page"`
	TotalPages      int            `json:"total_pages"`
	Query           string         `json:"query"`
	Vendor          string         `json:"vendor"`
	Product         string         `json:"product"`
	CVE             string         `json:"cve"`
	CWE             string         `json:"cwe"`
	StartDate       string         `json:"start_date"`
	EndDate         string         `json:"end_date"`
	KevOnly         bool           `json:"kev_only"`
	HasPoC          bool           `json:"has_poc"`
	MinCvss         float64        `json:"min_cvss"`
	MaxCvss         float64        `json:"max_cvss"`
	MinEpss         float64        `json:"min_epss"`
	MaxEpss         float64        `json:"max_epss"`
	SeverityCounts  SeverityCounts `json:"severity_counts"`
	TopCWEs         []CWEStat      `json:"top_cwes"`
	EPSSDist        []int          `json:"epss_dist"`
	MetaTitle       string         `json:"meta_title"`
	MetaDescription string         `json:"meta_description"`
	Trending        []models.CVE   `json:"trending"`
	Sort            string         `json:"sort"`
	Order           string         `json:"order"`
}

func (a *App) PublicDashboardHandler(w http.ResponseWriter, r *http.Request) {
	isAJAX := r.URL.Query().Get("ajax") == "true"
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

	cursorStr := r.URL.Query().Get("cursor")
	cursorIDStr := r.URL.Query().Get("cursor_id")
	if cursorStr != "" && cursorIDStr != "" {
		offset = 0 // override offset when using cursor pagination
	}

	searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	vendorQuery := strings.TrimSpace(r.URL.Query().Get("vendor"))
	productQuery := strings.TrimSpace(r.URL.Query().Get("product"))
	cveIDQuery := strings.TrimSpace(r.URL.Query().Get("cve"))
	cweQuery := strings.TrimSpace(r.URL.Query().Get("cwe"))

	startDate := strings.TrimSpace(r.URL.Query().Get("start_date"))
	endDate := strings.TrimSpace(r.URL.Query().Get("end_date"))
	kevOnly := r.URL.Query().Get("kev") == "true"
	hasPoC := r.URL.Query().Get("has_poc") == "true"
	minCvssStr := r.URL.Query().Get("min_cvss")
	maxCvssStr := r.URL.Query().Get("max_cvss")
	minEpssStr := r.URL.Query().Get("min_epss")
	maxEpssStr := r.URL.Query().Get("max_epss")

	minCvss, _ := strconv.ParseFloat(minCvssStr, 64)
	maxCvss, _ := strconv.ParseFloat(maxCvssStr, 64)
	if maxCvss == 0 {
		maxCvss = 10.0
	}
	minEpss, _ := strconv.ParseFloat(minEpssStr, 64)
	maxEpss, _ := strconv.ParseFloat(maxEpssStr, 64)
	if maxEpss == 0 && maxEpssStr != "" {
		// if user explicitly put 0, keep it. If empty, default to 1.0
	} else if maxEpssStr == "" {
		maxEpss = 1.0
	}

	// Normalize sort/order
	sort := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	order := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("order")))

	// Default sort
	if sort == "" {
		sort = "published"
	}
	if order != "asc" && order != "desc" {
		order = "desc"
	}

	// Redis Caching for Default View
	cacheKey := "public_dashboard_default_v2"
	if (r.URL.RawQuery == "" || r.URL.RawQuery == "page=1") && sort == "" && order == "" {
		if val, err := a.Redis.Get(r.Context(), cacheKey).Result(); err == nil {
			var cachedData PublicDashboardData
			if err := json.Unmarshal([]byte(val), &cachedData); err == nil {
				renderData := map[string]interface{}{
					"CVEs":           cachedData.CVEs,
					"Total":          cachedData.Total,
					"KevCount":       cachedData.KevCount,
					"CritCount":      cachedData.CritCount,
					"ThreatLevel":    cachedData.ThreatLevel,
					"ThreatColor":    cachedData.ThreatColor,
					"Page":           cachedData.Page,
					"TotalPages":     cachedData.TotalPages,
					"Query":          cachedData.Query,
					"Vendor":         cachedData.Vendor,
					"Product":        cachedData.Product,
					"CVE":            cachedData.CVE,
					"CWE":            cachedData.CWE,
					"StartDate":      cachedData.StartDate,
					"EndDate":        cachedData.EndDate,
					"KevOnly":        cachedData.KevOnly,
					"HasPoC":         cachedData.HasPoC,
					"MinCvss":        cachedData.MinCvss,
					"MaxCvss":        cachedData.MaxCvss,
					"MinEpss":        cachedData.MinEpss,
					"MaxEpss":        cachedData.MaxEpss,
					"SeverityCounts": cachedData.SeverityCounts,
					"TopCWEs":        cachedData.TopCWEs,
					"EPSSDist":       cachedData.EPSSDist,
					"Trending":       cachedData.Trending,
					"ActiveTab":      "cves",
					"CanScroll":      cachedData.Total > cachedData.Page*20,
					"csrfField":      csrf.TemplateField(r),
				}
				if isAJAX {
					a.renderAJAX(w, renderData)
					return
				}
				a.RenderTemplate(w, r, "public_dashboard.html", renderData)
				return
			}
		}
	}

	whereClause := " WHERE (1=1) "
	args := []any{}
	argIdx := 1

	if searchQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.cve_id ILIKE $%d OR c.description ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%"+escapeLikePattern(searchQuery)+"%")
		argIdx++
	}

	if vendorQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.vendor ILIKE $%d OR c.affected_products::text ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%"+escapeLikePattern(vendorQuery)+"%")
		argIdx++
	}

	if productQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.product ILIKE $%d OR c.affected_products::text ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%"+escapeLikePattern(productQuery)+"%")
		argIdx++
	}

	if cveIDQuery != "" {
		whereClause += fmt.Sprintf(" AND c.cve_id ILIKE $%d ", argIdx)
		args = append(args, "%"+escapeLikePattern(cveIDQuery)+"%")
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

	if cweQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.cwe_id ILIKE $%d OR c.cwe_name ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%"+escapeLikePattern(cweQuery)+"%")
		argIdx++
	}

	if hasPoC {
		whereClause += " AND c.github_poc_count > 0 "
	}

	if minEpss > 0 {
		whereClause += fmt.Sprintf(" AND c.epss_score >= $%d ", argIdx)
		args = append(args, minEpss)
		argIdx++
	}
	if maxEpss < 1.0 {
		whereClause += fmt.Sprintf(" AND c.epss_score <= $%d ", argIdx)
		args = append(args, maxEpss)
		argIdx++
	}

	var totalItems, kevCount, critCount int
	if whereClause == " WHERE (1=1) " {
		statsCache.RLock()
		totalItems = statsCache.total
		kevCount = statsCache.kevCount
		critCount = statsCache.critCount
		statsCache.RUnlock()
	} else {
		metricsQuery := `
			SELECT
				COUNT(DISTINCT c.id) as total_cves,
				COUNT(DISTINCT CASE WHEN c.cisa_kev = true THEN c.id END) as kev_count,
				COUNT(DISTINCT CASE WHEN c.cvss_score >= 9.0 THEN c.id END) as critical_count
			FROM cves c` + whereClause
		err := a.Pool.QueryRow(r.Context(), metricsQuery, args...).Scan(&totalItems, &kevCount, &critCount)
		if err != nil {
			log.Printf("Public dashboard metrics error: %v", err)
		}
	}

	query := `
		SELECT 
			c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, 
			c.published_date, c.updated_date, 'active' as status, COALESCE(c."references", '{}'),
			COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0),
			COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'),
			COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority
		FROM cves c
	`
	// Dynamic Sort
	sortCol := "c.published_date"
	sortOrder := "DESC"
	switch sort {
	case "id":
		sortCol = "c.cve_id"
	case "severity":
		sortCol = "c.cvss_score"
	case "epss":
		sortCol = "c.epss_score"
	case "published":
		sortCol = "c.published_date"
	}
	if strings.ToUpper(order) == "ASC" {
		sortOrder = "ASC"
	}

	if cursorStr != "" && cursorIDStr != "" {
		cursorID, err := strconv.Atoi(cursorIDStr)
		if err == nil && cursorID > 0 {
			op := "<"
			if sortOrder == "ASC" {
				op = ">"
			}

			// Validate cursorStr based on sort column
			var parseErr error
			switch sortCol {
			case "c.published_date":
				_, parseErr = time.Parse(time.RFC3339Nano, cursorStr)
				if parseErr != nil {
					_, parseErr = time.Parse(time.RFC3339, cursorStr)
				}
				if parseErr != nil {
					_, parseErr = time.Parse("2006-01-02 15:04:05.999999-07", cursorStr)
				}
			case "c.cvss_score", "c.epss_score":
				_, parseErr = strconv.ParseFloat(cursorStr, 64)
			}
			if parseErr != nil {
				http.Error(w, "Invalid cursor value", http.StatusBadRequest)
				return
			}

			var castType string
			switch sortCol {
			case "c.published_date":
				castType = "::timestamptz"
			case "c.cvss_score", "c.epss_score":
				castType = "::numeric"
			default:
				castType = ""
			}
			keysetCond := fmt.Sprintf(" AND (%s %s $%d%s OR (%s = $%d%s AND c.id < $%d)) ", sortCol, op, argIdx, castType, sortCol, argIdx+1, castType, argIdx+2)
			whereClause += keysetCond
			args = append(args, cursorStr, cursorStr, cursorID)
			argIdx += 3
		}
	}

	query += whereClause
	query += fmt.Sprintf(" ORDER BY %s %s NULLS LAST, c.id DESC LIMIT $%d OFFSET $%d ", sortCol, sortOrder, argIdx, argIdx+1)
	finalArgs := append(args, pageSize, offset)
	var cves []models.CVE
	rows, err := a.Pool.Query(r.Context(), query, finalArgs...)
	if err != nil {
		log.Printf("Public dashboard query error: %v", err)
		totalItems = 0
	} else {
		defer rows.Close()
		for rows.Next() {
			var c models.CVE
			err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount, &c.GreyNoiseHits, &c.GreyNoiseClass, &c.OSVData, &c.Vendor, &c.Product, &c.AffectedProducts, &c.Priority)
			if err != nil {
				log.Printf("Error scanning public CVE: %v", err)
				continue
			}
			c.CWEName = models.GetCWEName(c.CWEID, c.CWEName)
			_ = a.Pool.QueryRow(r.Context(), "SELECT cisa_ransomware FROM cves WHERE id = $1", c.ID).Scan(&c.CISARansomware)
			cves = append(cves, c)
		}
	}

	totalPages := (totalItems + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	threatLevel := "LOW"
	threatColor := "text-blue-400"
	if kevCount > 0 || critCount > 0 {
		threatLevel = "HIGH"
		threatColor = "text-red-500"
	}

	var severityCounts SeverityCounts
	var topCWEs []CWEStat
	var epssDist []int

	if whereClause == " WHERE (1=1) " {
		statsCache.RLock()
		severityCounts = statsCache.severityCounts
		topCWEs = statsCache.topCWEs
		epssDist = statsCache.epssDist
		statsCache.RUnlock()
	} else {
		severityQuery := "SELECT " +
			"COUNT(*) FILTER (WHERE cvss_score >= 9.0), " +
			"COUNT(*) FILTER (WHERE cvss_score >= 7.0 AND cvss_score < 9.0), " +
			"COUNT(*) FILTER (WHERE cvss_score >= 4.0 AND cvss_score < 7.0), " +
			"COUNT(*) FILTER (WHERE cvss_score < 4.0) " +
			"FROM cves c " + whereClause
		_ = a.Pool.QueryRow(r.Context(), severityQuery, args...).Scan(&severityCounts.Critical, &severityCounts.High, &severityCounts.Medium, &severityCounts.Low)

		cweQueryRows, _ := a.Pool.Query(r.Context(), "SELECT cwe_id, COALESCE(MAX(cwe_name), 'Unknown'), COUNT(*) as cnt FROM cves c "+whereClause+" AND cwe_id IS NOT NULL AND cwe_id != '' GROUP BY cwe_id ORDER BY cnt DESC LIMIT 15", args...)
		if cweQueryRows != nil {
			for cweQueryRows.Next() {
				var s CWEStat
				if err := cweQueryRows.Scan(&s.ID, &s.Name, &s.Count); err == nil {
					s.Name = models.GetCWEName(s.ID, s.Name)
					topCWEs = append(topCWEs, s)
				}
			}
			cweQueryRows.Close()
		}

		epssQuery := "SELECT " +
			"COUNT(*) FILTER (WHERE epss_score < 0.01), " +
			"COUNT(*) FILTER (WHERE epss_score >= 0.01 AND epss_score < 0.1), " +
			"COUNT(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5), " +
			"COUNT(*) FILTER (WHERE epss_score >= 0.5) " +
			"FROM cves c " + whereClause
		var e1, e2, e3, e4 int
		_ = a.Pool.QueryRow(r.Context(), epssQuery, args...).Scan(&e1, &e2, &e3, &e4)
		epssDist = []int{e1, e2, e3, e4}
	}

	renderData := map[string]interface{}{
		"CVEs":            cves,
		"Total":           totalItems,
		"KevCount":        kevCount,
		"CritCount":       critCount,
		"ThreatLevel":     threatLevel,
		"ThreatColor":     threatColor,
		"Page":            page,
		"TotalPages":      totalPages,
		"Query":           searchQuery,
		"Vendor":          vendorQuery,
		"Product":         productQuery,
		"CVE":             cveIDQuery,
		"CWE":             cweQuery,
		"StartDate":       startDate,
		"EndDate":         endDate,
		"KevOnly":         kevOnly,
		"HasPoC":          hasPoC,
		"MinCvss":         minCvss,
		"MaxCvss":         maxCvss,
		"MinEpss":         minEpss,
		"MaxEpss":         maxEpss,
		"SeverityCounts":  severityCounts,
		"TopCWEs":         topCWEs,
		"EPSSDist":        epssDist,
		"Sort":            sort,
		"Order":           order,
		"MetaTitle":       "Vulfixx - CVE Tracker",
		"MetaDescription": "Monitor real-time vulnerability data, CISA KEV listings, and critical security advisories. The ultimate tracker for security professionals.",
		"Trending":        a.getTrendingCVEs(r),
		"csrfField":       csrf.TemplateField(r),
	}

	// Cache Default View
	if r.URL.RawQuery == "" || r.URL.RawQuery == "page=1" {
		// Use struct for consistent JSON
		cachedData := PublicDashboardData{
			CVEs:            cves,
			Total:           totalItems,
			KevCount:        kevCount,
			CritCount:       critCount,
			ThreatLevel:     threatLevel,
			ThreatColor:     threatColor,
			Page:            page,
			TotalPages:      totalPages,
			Query:           searchQuery,
			Vendor:          vendorQuery,
			Product:         productQuery,
			CVE:             cveIDQuery,
			CWE:             cweQuery,
			StartDate:       startDate,
			EndDate:         endDate,
			KevOnly:         kevOnly,
			HasPoC:          hasPoC,
			MinCvss:         minCvss,
			MaxCvss:         maxCvss,
			MinEpss:         minEpss,
			MaxEpss:         maxEpss,
			SeverityCounts:  severityCounts,
			TopCWEs:         topCWEs,
			EPSSDist:        epssDist,
			MetaTitle:       renderData["MetaTitle"].(string),
			MetaDescription: renderData["MetaDescription"].(string),
			Trending:        renderData["Trending"].([]models.CVE),
		}
		if jsonData, err := json.Marshal(cachedData); err == nil {
			_ = a.Redis.Set(r.Context(), cacheKey, jsonData, 5*time.Minute).Err()
		}
	}

	if isAJAX {
		a.renderAJAX(w, renderData)
		return
	}

	a.RenderTemplate(w, r, "public_dashboard.html", renderData)
}

func (a *App) getTrendingCVEs(r *http.Request) []models.CVE {
	rows, err := a.Pool.Query(r.Context(), `
		SELECT 
			c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, 
			c.published_date, c.updated_date, 'active' as status, c."references",
			COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0),
			COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'),
			COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]')
		FROM cves c
		WHERE c.cisa_kev = true OR c.cvss_score >= 9.5 OR c.github_poc_count > 0 OR c.epss_score >= 0.5
		ORDER BY c.github_poc_count DESC, c.epss_score DESC, c.published_date DESC NULLS LAST, c.id DESC LIMIT 100
	`)
	if err != nil {
		log.Printf("Error querying trending CVEs: %v", err)
		return nil
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount, &c.GreyNoiseHits, &c.GreyNoiseClass, &c.OSVData, &c.Vendor, &c.Product, &c.AffectedProducts); err != nil {
			log.Printf("Error scanning trending CVE: %v", err)
			continue
		}
		cves = append(cves, c)
	}
	return cves
}

func (a *App) CVEDetailHandler(w http.ResponseWriter, r *http.Request) {
	cveID := chi.URLParam(r, "id")

	c := &models.CVE{}
	err := a.Pool.QueryRow(r.Context(), `
		SELECT 
			id, cve_id, description, COALESCE(cvss_score, 0), vector_string, cisa_kev, 
			published_date, updated_date, 'active' as status, "references", 
			COALESCE(epss_score, 0), COALESCE(cwe_id, ''), COALESCE(cwe_name, ''), COALESCE(github_poc_count, 0),
			COALESCE(greynoise_hits, 0), COALESCE(greynoise_classification, ''), osv_data,
			configurations, COALESCE(vendor, ''), COALESCE(product, ''), COALESCE(affected_products, '[]'),
			COALESCE(priority, 'P3') as priority
		FROM cves
		WHERE cve_id = $1
	`, cveID).Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount, &c.GreyNoiseHits, &c.GreyNoiseClass, &c.OSVData, &c.Configurations, &c.Vendor, &c.Product, &c.AffectedProducts, &c.Priority)

	c.CWEName = models.GetCWEName(c.CWEID, c.CWEName)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			log.Printf("CVEDetailHandler error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Fetch cisa_ransomware separately to avoid breaking test mocks of the primary query
	_ = a.Pool.QueryRow(r.Context(), "SELECT cisa_ransomware FROM cves WHERE cve_id = $1", c.CVEID).Scan(&c.CISARansomware)

	// Fetch threat actor and ransomware associations
	var threatAssociations []models.ThreatAssociation
	taRows, taErr := a.Pool.Query(r.Context(), `
		SELECT id, cve_id, entity_name, entity_type, source, created_at
		FROM cve_threat_associations
		WHERE cve_id = $1
		ORDER BY entity_name ASC
	`, c.CVEID)
	if taErr == nil {
		defer taRows.Close()
		for taRows.Next() {
			var ta models.ThreatAssociation
			if err := taRows.Scan(&ta.ID, &ta.CVEID, &ta.EntityName, &ta.EntityType, &ta.Source, &ta.CreatedAt); err == nil {
				threatAssociations = append(threatAssociations, ta)
			}
		}
	}

	var prevID, nextID string
	if !c.PublishedDate.IsZero() {
		// Next (older)
		_ = a.Pool.QueryRow(r.Context(), `
			SELECT cve_id FROM cves 
			WHERE published_date < $1 OR (published_date = $1 AND id < $2) 
			ORDER BY published_date DESC, id DESC LIMIT 1
		`, c.PublishedDate, c.ID).Scan(&nextID)

		// Prev (newer)
		_ = a.Pool.QueryRow(r.Context(), `
			SELECT cve_id FROM cves 
			WHERE published_date > $1 OR (published_date = $1 AND id > $2) 
			ORDER BY published_date ASC, id ASC LIMIT 1
		`, c.PublishedDate, c.ID).Scan(&prevID)
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

	// Fetch user assets if logged in for automatic matching
	var userAssets []map[string]interface{}
	if userID, ok := a.GetUserID(r); ok {
		rows, err := a.Pool.Query(r.Context(), `
			SELECT a.name, COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}')
			FROM assets a
			LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
			WHERE a.user_id = $1 OR a.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1)
			GROUP BY a.id, a.name
		`, userID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var name string
				var keywords []string
				if err := rows.Scan(&name, &keywords); err == nil {
					userAssets = append(userAssets, map[string]interface{}{
						"name":     name,
						"keywords": keywords,
					})
				}
			}
		}
	}

	a.RenderTemplate(w, r, "cve_detail.html", map[string]interface{}{
		"CVE":                c,
		"prevID":             prevID,
		"nextID":             nextID,
		"MetaTitle":          fmt.Sprintf("%s - %s | Vulfixx Threat Intel", c.CVEID, c.Description),
		"MetaDescription":    fmt.Sprintf("Security analysis of %s. Severity: %.1f. %s", c.CVEID, c.CVSSScore, c.Description),
		"Canonical":          fmt.Sprintf("/cve/%s", c.CVEID),
		"UserAssets":         userAssets,
		"ThreatAssociations": threatAssociations,
		/* #nosec G203 */
		"JSONLD": template.JS(safeJSONLD), // safe: JSON-marshaled then </script>-escaped
	})
}

func (a *App) renderAJAX(w http.ResponseWriter, renderData map[string]interface{}) {
	a.TemplateMu.RLock()
	tmpl, ok := a.TemplateMap["public_dashboard.html"]
	a.TemplateMu.RUnlock()
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "cve_rows", renderData); err != nil {
		log.Printf("Error executing AJAX template: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"html": buf.String(),
		"meta": renderData,
	}); err != nil {
		log.Printf("Error encoding AJAX JSON response: %v", err)
	}
}

// APICVEsHandler exposes keyset cursor pagination over JSON API (Item 23)
// @Summary Get CVEs with Keyset Cursor Pagination
// @Description Retrieve a paginated list of CVEs using keyset/cursor pagination.
// @Tags CVEs
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor timestamp/published date"
// @Param cursor_id query string false "Cursor CVE ID"
// @Param limit query int false "Limit the number of results" default(20)
// @Param sort query string false "Sort field (published, id)" default("published")
// @Param order query string false "Sort order (asc, desc)" default("desc")
// @Success 200 {object} APIResponse "Standard API response envelope containing CVEs list"
// @Failure 400 {object} APIResponse "Bad Request"
// @Router /api/cves [get]
func (a *App) APICVEsHandler(w http.ResponseWriter, r *http.Request) {
	cursorStr := r.URL.Query().Get("cursor")
	cursorIDStr := r.URL.Query().Get("cursor_id")
	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
			if limit > 100 {
				limit = 100
			}
		}
	}

	sort := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	order := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("order")))

	// Default sort
	if sort == "" {
		sort = "published"
	}
	if order != "asc" && order != "desc" {
		order = "desc"
	}

	sortCol := "c.published_date"
	sortOrder := "DESC"
	switch sort {
	case "id":
		sortCol = "c.cve_id"
	case "severity":
		sortCol = "c.cvss_score"
	case "epss":
		sortCol = "c.epss_score"
	case "published":
		sortCol = "c.published_date"
	}
	if strings.ToUpper(order) == "ASC" {
		sortOrder = "ASC"
	}

	whereClause := " WHERE (1=1) "
	var args []interface{}
	argIdx := 1

	if cursorStr != "" && cursorIDStr != "" {
		cursorID, err := strconv.Atoi(cursorIDStr)
		if err == nil && cursorID > 0 {
			op := "<"
			if sortOrder == "ASC" {
				op = ">"
			}

			// Validate cursorStr based on sort column
			var parseErr error
			switch sortCol {
			case "c.published_date":
				_, parseErr = time.Parse(time.RFC3339Nano, cursorStr)
				if parseErr != nil {
					_, parseErr = time.Parse(time.RFC3339, cursorStr)
				}
				if parseErr != nil {
					_, parseErr = time.Parse("2006-01-02 15:04:05.999999-07", cursorStr)
				}
			case "c.cvss_score", "c.epss_score":
				_, parseErr = strconv.ParseFloat(cursorStr, 64)
			}
			if parseErr == nil {
				var castType string
				switch sortCol {
				case "c.published_date":
					castType = "::timestamptz"
				case "c.cvss_score", "c.epss_score":
					castType = "::numeric"
				}
				keysetCond := fmt.Sprintf(" AND (%s %s $%d%s OR (%s = $%d%s AND c.id < $%d)) ", sortCol, op, argIdx, castType, sortCol, argIdx+1, castType, argIdx+2)
				whereClause += keysetCond
				args = append(args, cursorStr, cursorStr, cursorID)
				argIdx += 3
			}
		}
	}

	query := `
		SELECT 
			c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, 
			c.published_date, c.updated_date, 'active' as status, COALESCE(c."references", '{}'),
			COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0),
			COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'),
			COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority
		FROM cves c
	`
	query += whereClause
	query += fmt.Sprintf(" ORDER BY %s %s NULLS LAST, c.id DESC LIMIT $%d ", sortCol, sortOrder, argIdx)
	args = append(args, limit)

	rows, err := a.Pool.Query(r.Context(), query, args...)
	if err != nil {
		log.Printf("Error querying CVEs: %v", err)
		SendJSONResponse(w, http.StatusInternalServerError, false, nil, "Failed to fetch CVE data", nil)
		return
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount, &c.GreyNoiseHits, &c.GreyNoiseClass, &c.OSVData, &c.Vendor, &c.Product, &c.AffectedProducts, &c.Priority); err != nil {
			log.Printf("Error scanning CVE row: %v", err)
			SendJSONResponse(w, http.StatusInternalServerError, false, nil, "Failed to fetch CVE data", nil)
			return
		}
		cves = append(cves, c)
	}

	var nextCursor string
	var nextCursorID int
	if len(cves) > 0 {
		lastCVE := cves[len(cves)-1]
		nextCursorID = lastCVE.ID
		switch sort {
		case "severity":
			nextCursor = fmt.Sprintf("%f", lastCVE.CVSSScore)
		case "epss":
			nextCursor = fmt.Sprintf("%f", lastCVE.EPSSScore)
		case "id":
			nextCursor = lastCVE.CVEID
		default: // published
			nextCursor = lastCVE.PublishedDate.Format(time.RFC3339Nano)
		}
	}

	meta := map[string]interface{}{
		"limit":          limit,
		"sort":           sort,
		"order":          order,
		"next_cursor":    nextCursor,
		"next_cursor_id": nextCursorID,
		"count":          len(cves),
	}

	SendJSONResponse(w, http.StatusOK, true, cves, "", meta)
}

func (a *App) parseDashboardFilters(r *http.Request, userID int, activeTeamID int) dashboardFilters {
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

	validStatuses := map[string]bool{"active": true, "in_progress": true, "resolved": true, "ignored": true}
	if statusFilter != "" && !validStatuses[statusFilter] {
		statusFilter = ""
	}
	kevOnly := r.URL.Query().Get("kev") == "true"
	minCvssStr := r.URL.Query().Get("min_cvss")
	maxCvssStr := r.URL.Query().Get("max_cvss")

	minCvss, _ := strconv.ParseFloat(minCvssStr, 64)
	maxCvss, _ := strconv.ParseFloat(maxCvssStr, 64)
	if maxCvss == 0 {
		maxCvss = 10.0
	}

	return dashboardFilters{
		userID:       userID,
		activeTeamID: activeTeamID,
		page:         page,
		pageSize:     pageSize,
		offset:       offset,
		searchQuery:  searchQuery,
		startDate:    startDate,
		endDate:      endDate,
		searchAll:    searchAll,
		statusFilter: statusFilter,
		kevOnly:      kevOnly,
		minCvss:      minCvss,
		maxCvss:      maxCvss,
	}
}

func (a *App) buildDashboardWhereClause(f dashboardFilters) (string, []any, int, string, int) {
	args := []any{f.userID}
	argIdx := 2

	teamArgIdx := -1
	statusJoinCond := "ucs.user_id = $1 AND ucs.team_id IS NULL"
	if f.activeTeamID > 0 {
		statusJoinCond = fmt.Sprintf("ucs.team_id = $%d", argIdx)
		teamArgIdx = argIdx
		args = append(args, f.activeTeamID)
		argIdx++
	}

	whereClause := " WHERE (1=1) "
	if !f.searchAll {
		whereClause += fmt.Sprintf(` AND (
			EXISTS (
				SELECT 1 FROM user_subscriptions us
				WHERE (us.user_id = $1 OR us.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1))
				  AND c.cvss_score >= us.min_severity
				  AND (us.keyword = '' OR c.description ILIKE '%%' || us.keyword || '%%')
			)
		) `)
		whereClause += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
	} else {
		if f.statusFilter == "" || f.statusFilter == "active" {
			whereClause += " AND (ucs.status IS NULL OR (ucs.status != 'resolved' AND ucs.status != 'ignored')) "
		} else if f.statusFilter != "" {
			whereClause += fmt.Sprintf(" AND ucs.status = $%d ", argIdx)
			args = append(args, f.statusFilter)
			argIdx++
		}
	}

	if f.searchQuery != "" {
		whereClause += fmt.Sprintf(" AND (c.cve_id ILIKE $%d OR c.description ILIKE $%d) ", argIdx, argIdx)
		args = append(args, "%%"+escapeLikePattern(f.searchQuery)+"%%")
		argIdx++
	}
	if f.kevOnly {
		whereClause += " AND c.cisa_kev = true "
	}
	if f.minCvss > 0 {
		whereClause += fmt.Sprintf(" AND c.cvss_score >= $%d ", argIdx)
		args = append(args, f.minCvss)
		argIdx++
	}
	if f.maxCvss < 10 {
		whereClause += fmt.Sprintf(" AND c.cvss_score <= $%d ", argIdx)
		args = append(args, f.maxCvss)
		argIdx++
	}
	if f.startDate != "" {
		whereClause += fmt.Sprintf(" AND c.published_date >= $%d ", argIdx)
		args = append(args, f.startDate)
		argIdx++
	}
	if f.endDate != "" {
		whereClause += fmt.Sprintf(" AND c.published_date <= $%d ", argIdx)
		args = append(args, f.endDate)
		argIdx++
	}

	return whereClause, args, argIdx, statusJoinCond, teamArgIdx
}

func (a *App) fetchDashboardMetrics(ctx context.Context, f dashboardFilters, statusJoinCond string, whereClause string, args []any) dashboardMetrics {
	var metrics dashboardMetrics
	consolidatedMetricsQuery := fmt.Sprintf(`
		SELECT
			COUNT(c.id) as total_cves,
			COUNT(CASE WHEN c.cisa_kev = true THEN 1 END) as kev_count,
			COUNT(CASE WHEN c.cvss_score >= 9.0 THEN 1 END) as critical_count,
			COUNT(CASE WHEN ucs.status = 'in_progress' THEN 1 END) as in_progress_count,
			-- Severity
			COUNT(CASE WHEN c.cvss_score >= 9.0 THEN 1 END) as sev_crit,
			COUNT(CASE WHEN c.cvss_score >= 7.0 AND c.cvss_score < 9.0 THEN 1 END) as sev_high,
			COUNT(CASE WHEN c.cvss_score >= 4.0 AND c.cvss_score < 7.0 THEN 1 END) as sev_med,
			COUNT(CASE WHEN c.cvss_score < 4.0 THEN 1 END) as sev_low,
			-- Status
			COUNT(CASE WHEN COALESCE(ucs.status, 'active') = 'active' THEN 1 END) as stat_active,
			COUNT(CASE WHEN ucs.status = 'in_progress' THEN 1 END) as stat_prog,
			COUNT(CASE WHEN ucs.status = 'resolved' THEN 1 END) as stat_res,
			COUNT(CASE WHEN ucs.status = 'ignored' THEN 1 END) as stat_ign
		FROM cves c
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND %s
		%s
	`, statusJoinCond, whereClause)

	cacheKeyStr := fmt.Sprintf("%d:%d:%s:%v", f.userID, f.activeTeamID, consolidatedMetricsQuery, args)
	cacheKeyHash := sha256.Sum256([]byte(cacheKeyStr))
	cacheKey := fmt.Sprintf("dashboard_metrics_v2:%x", cacheKeyHash)

	if cachedData, err := a.Redis.Get(ctx, cacheKey).Result(); err == nil {
		if err := json.Unmarshal([]byte(cachedData), &metrics); err == nil {
			return metrics
		}
	}

	if err := a.Pool.QueryRow(ctx, consolidatedMetricsQuery, args...).Scan(
		&metrics.Total, &metrics.Kev, &metrics.Critical, &metrics.InProgress,
		&metrics.SevCrit, &metrics.SevHigh, &metrics.SevMed, &metrics.SevLow,
		&metrics.StatActive, &metrics.StatProg, &metrics.StatRes, &metrics.StatIgn,
	); err != nil {
		log.Printf("Dashboard consolidated metrics error: %v", err)
	} else {
		if dataToCache, err := json.Marshal(metrics); err == nil {
			a.Redis.SetEx(ctx, cacheKey, dataToCache, 60*time.Second)
		}
	}
	return metrics
}

func (a *App) fetchDashboardCVEs(ctx context.Context, f dashboardFilters, statusJoinCond string, teamArgIdx int, whereClause string, args []any, argIdx int) []models.CVE {
	notesJoinCond := "ucn.user_id = $1 AND ucn.team_id IS NULL"
	if teamArgIdx != -1 {
		notesJoinCond = fmt.Sprintf("ucn.team_id = $%d", teamArgIdx)
	}

	query := fmt.Sprintf(`
		SELECT c.id, c.cve_id, c.description, COALESCE(c.cvss_score, 0), c.vector_string, c.cisa_kev, c.published_date, c.updated_date, COALESCE(ucs.status, 'active') as status, COALESCE(c."references", '{}'), ucn.notes,
		COALESCE(c.epss_score, 0), COALESCE(c.cwe_id, ''), COALESCE(c.cwe_name, ''), COALESCE(c.github_poc_count, 0), COALESCE(c.greynoise_hits, 0), COALESCE(c.greynoise_classification, ''), COALESCE(c.osv_data, '{}'), COALESCE(c.vendor, ''), COALESCE(c.product, ''), COALESCE(c.affected_products, '[]'), COALESCE(c.priority, 'P3') as priority
		FROM cves c
		LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND %s
		LEFT JOIN cve_notes ucn ON c.id = ucn.cve_id AND %s
	`, statusJoinCond, notesJoinCond)

	query += whereClause
	query += fmt.Sprintf(" ORDER BY c.published_date DESC NULLS LAST, c.id DESC LIMIT $%d OFFSET $%d ", argIdx, argIdx+1)

	finalArgs := append(args, f.pageSize, f.offset)

	rows, err := a.Pool.Query(ctx, query, finalArgs...)
	if err != nil {
		log.Printf("Dashboard query error: %v", err)
		return nil
	}
	defer rows.Close()

	var cves []models.CVE
	for rows.Next() {
		var c models.CVE
		var notes sql.NullString
		if err := rows.Scan(&c.ID, &c.CVEID, &c.Description, &c.CVSSScore, &c.VectorString, &c.CISAKEV, &c.PublishedDate, &c.UpdatedDate, &c.Status, &c.References, &notes, &c.EPSSScore, &c.CWEID, &c.CWEName, &c.GitHubPoCCount, &c.GreyNoiseHits, &c.GreyNoiseClass, &c.OSVData, &c.Vendor, &c.Product, &c.AffectedProducts, &c.Priority); err != nil {
			log.Printf("Error scanning dashboard CVE row (CVEID=%s): %v", c.CVEID, err)
			continue
		}
		c.Notes = notes.String
		c.CWEName = models.GetCWEName(c.CWEID, c.CWEName)
		_ = a.Pool.QueryRow(ctx, "SELECT cisa_ransomware FROM cves WHERE id = $1", c.ID).Scan(&c.CISARansomware)
		cves = append(cves, c)
	}
	return cves
}

func (a *App) fetchTopCWEs(ctx context.Context, statusJoinCond string, whereClause string, args []any) []CWEStat {
	var topCWEs []CWEStat
	cweBaseQuery := "SELECT cwe_id, COALESCE(MAX(cwe_name), 'Unknown'), COUNT(c.id) as cnt FROM cves c "
	cweBaseQuery += fmt.Sprintf(" LEFT JOIN user_cve_status ucs ON c.id = ucs.cve_id AND %s ", statusJoinCond)
	cweQuery := cweBaseQuery + whereClause + " AND cwe_id IS NOT NULL AND cwe_id != '' GROUP BY cwe_id ORDER BY cnt DESC LIMIT 15"

	cweQueryRows, err := a.Pool.Query(ctx, cweQuery, args...)
	if err != nil {
		log.Printf("CWE distribution error: %v", err)
	} else {
		defer cweQueryRows.Close()
		for cweQueryRows.Next() {
			var s CWEStat
			if err := cweQueryRows.Scan(&s.ID, &s.Name, &s.Count); err == nil {
				s.Name = models.GetCWEName(s.ID, s.Name)
				topCWEs = append(topCWEs, s)
			}
		}
	}
	return topCWEs
}
