package web

import (
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func AssetsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "GET" {
		rows, err := db.Pool.Query(r.Context(), `
			SELECT a.id, a.name, a.type, a.created_at, 
			       COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}'),
			       COALESCE(t.name, '') as team_name
			FROM assets a
			LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
			LEFT JOIN teams t ON a.team_id = t.id
			WHERE a.user_id = $1 OR a.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1)
			GROUP BY a.id, t.name
			ORDER BY a.created_at DESC
		`, userID)
		if err != nil {
			log.Printf("Error fetching assets: %v", err)
			http.Error(w, "Error fetching assets", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type AssetWithKeywords struct {
			models.Asset
			Keywords []string
			TeamName string
		}
		var assets []AssetWithKeywords
		for rows.Next() {
			var a AssetWithKeywords
			if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.CreatedAt, &a.Keywords, &a.TeamName); err != nil {
				continue
			}
			assets = append(assets, a)
		}
		RenderTemplate(w, r, "assets.html", map[string]interface{}{"Assets": assets})
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			SendResponse(w, r, false, "", "", "Error parsing form")
			return
		}
		name := r.FormValue("name")
		assetType := r.FormValue("type")
		keywords := r.FormValue("keywords")
		teamIDStr := r.FormValue("team_id")

		var teamID *int
		if teamIDStr != "" && teamIDStr != "0" {
			tid, err := strconv.Atoi(teamIDStr)
			if err == nil {
				teamID = &tid
			}
		}

		if len(name) < 1 || len(name) > 255 {
			SendResponse(w, r, false, "", "", "Asset name must be between 1 and 255 characters")
			return
		}
		allowedTypes := map[string]bool{
			"Server":   true,
			"Software": true,
			"Network":  true,
			"Cloud":    true,
			"IoT":      true,
		}
		if !allowedTypes[assetType] {
			SendResponse(w, r, false, "", "", "Invalid asset category")
			return
		}

		tx, err := db.Pool.Begin(r.Context())
		if err != nil {
			SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var assetID int
		err = tx.QueryRow(r.Context(), `
			INSERT INTO assets (user_id, team_id, name, type) VALUES ($1, $2, $3, $4) RETURNING id
		`, userID, teamID, name, assetType).Scan(&assetID)
		if err != nil {
			log.Printf("Error creating asset: %v", err)
			SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		if keywords != "" {
			kwList := strings.Split(keywords, ",")
			for _, kw := range kwList {
				kw = strings.TrimSpace(kw)
				if kw != "" {
					_, err = tx.Exec(r.Context(), `
						INSERT INTO asset_keywords (asset_id, keyword) VALUES ($1, $2)
						ON CONFLICT DO NOTHING
					`, assetID, kw)
					if err != nil {
						SendResponse(w, r, false, "", "", "Error adding keyword")
						return
					}
				}
			}
		}

		if err = tx.Commit(r.Context()); err != nil {
			SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		LogActivity(r.Context(), userID, "asset_registered", fmt.Sprintf("Registered asset %q", name), r.RemoteAddr, r.UserAgent())
		SendResponse(w, r, true, "Asset registered successfully", "/assets", "")
	}
}

func DeleteAssetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}
	userID, ok := GetUserID(r)
	if !ok {
		SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}
	idStr := r.FormValue("id")
	assetID, err := strconv.Atoi(idStr)
	if err != nil {
		SendResponse(w, r, false, "", "", "Invalid asset ID")
		return
	}
	_, err = db.Pool.Exec(r.Context(), "DELETE FROM assets WHERE id = $1 AND (user_id = $2 OR team_id IN (SELECT team_id FROM team_members WHERE user_id = $2 AND role IN ('owner', 'admin')))", assetID, userID)
	if err != nil {
		SendResponse(w, r, false, "", "", "Error deleting asset")
		return
	}

	LogActivity(r.Context(), userID, "asset_deleted", fmt.Sprintf("Deleted asset ID %d", assetID), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Asset removed successfully", "/assets", "")
}
