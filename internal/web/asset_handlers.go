package web

import (
	"cve-tracker/internal/models"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) AssetsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "GET" {
		rows, err := a.Pool.Query(r.Context(), `
			SELECT a.id, a.name, COALESCE(a.type, ''), a.created_at, 
			       COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}'),
			       COALESCE(t.name, '') as team_name
			FROM assets a
			LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
			LEFT JOIN teams t ON a.team_id = t.id
			WHERE a.user_id = $1 OR a.team_id IN (SELECT team_id FROM team_members WHERE user_id = $1)
			GROUP BY a.id, t.id, t.name
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
			var as AssetWithKeywords
			if err := rows.Scan(&as.ID, &as.Name, &as.Type, &as.CreatedAt, &as.Keywords, &as.TeamName); err != nil {
				log.Printf("Error scanning asset row: %v", err)
				http.Error(w, "Error parsing assets", http.StatusInternalServerError)
				return
			}
			assets = append(assets, as)
		}
		if err := rows.Err(); err != nil {
			log.Printf("Error iterating asset rows: %v", err)
			http.Error(w, "Error fetching assets", http.StatusInternalServerError)
			return
		}
		a.RenderTemplate(w, r, "assets.html", map[string]interface{}{"Assets": assets})
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			a.SendResponse(w, r, false, "", "", "Error parsing form")
			return
		}
		name := r.FormValue("name")
		assetType := r.FormValue("type")
		keywords := r.FormValue("keywords")
		teamIDStr := r.FormValue("team_id")

		var teamID *int
		if teamIDStr != "" && teamIDStr != "0" {
			tid, err := strconv.Atoi(teamIDStr)
			if err != nil {
				a.SendResponse(w, r, false, "", "", "Invalid team_id")
				return
			}
			teamID = &tid
			// Verify membership
			var isMember bool
			err = a.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", tid, userID).Scan(&isMember)
			if err != nil || !isMember {
				a.SendResponse(w, r, false, "", "", "You are not a member of this team")
				return
			}
		}

		if len(name) < 1 || len(name) > 255 {
			a.SendResponse(w, r, false, "", "", "Asset name must be between 1 and 255 characters")
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
			a.SendResponse(w, r, false, "", "", "Invalid asset category")
			return
		}

		var kwList []string
		if keywords != "" {
			rawKws := strings.Split(keywords, ",")
			for _, kw := range rawKws {
				kw = strings.TrimSpace(kw)
				if kw != "" {
					if len(kw) > 50 {
						a.SendResponse(w, r, false, "", "", "Keyword too long (maximum 50 characters)")
						return
					}
					kwList = append(kwList, kw)
				}
			}
			if len(kwList) > 10 {
				a.SendResponse(w, r, false, "", "", "Too many keywords (maximum 10)")
				return
			}
		}

		ctx := r.Context()
		tx, err := a.Pool.Begin(ctx)
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		// Enforce Quota
		var currentCount int
		var maxAssets int
		if teamID != nil {
			// Re-verify membership inside transaction
			var exists bool
			err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", *teamID, userID).Scan(&exists)
			if err != nil || !exists {
				a.SendResponse(w, r, false, "", "", "Permission denied")
				return
			}
			err = tx.QueryRow(ctx, "SELECT max_assets FROM teams WHERE id = $1 FOR UPDATE", *teamID).Scan(&maxAssets)
			if err != nil {
				a.SendResponse(w, r, false, "", "", "Internal server error")
				return
			}
			err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM assets WHERE team_id = $1", *teamID).Scan(&currentCount)
		} else {
			err = tx.QueryRow(ctx, "SELECT max_assets FROM users WHERE id = $1 FOR UPDATE", userID).Scan(&maxAssets)
			if err != nil {
				a.SendResponse(w, r, false, "", "", "Internal server error")
				return
			}
			err = tx.QueryRow(ctx, "SELECT COUNT(*) FROM assets WHERE user_id = $1 AND team_id IS NULL", userID).Scan(&currentCount)
		}
		if err != nil {
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		if currentCount >= maxAssets {
			a.SendResponse(w, r, false, "", "", fmt.Sprintf("Maximum of %d assets allowed for this %s", maxAssets, func() string {
				if teamID != nil {
					return "team"
				}
				return "account"
			}()))
			return
		}

		var assetID int
		err = tx.QueryRow(ctx, `
			INSERT INTO assets (user_id, team_id, name, type) VALUES ($1, $2, $3, $4) RETURNING id
		`, userID, teamID, name, assetType).Scan(&assetID)
		if err != nil {
			log.Printf("Error creating asset: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		if len(kwList) > 0 {
			for _, kw := range kwList {
				if kw == "" {
					continue
				}
				_, err = tx.Exec(ctx, `
					INSERT INTO asset_keywords (asset_id, keyword) VALUES ($1, $2)
					ON CONFLICT DO NOTHING
				`, assetID, kw)
				if err != nil {
					a.SendResponse(w, r, false, "", "", "Error adding keyword")
					return
				}
			}
		}

		if err = tx.Commit(ctx); err != nil {
			a.SendResponse(w, r, false, "", "", "Internal server error")
			return
		}

		a.LogActivity(ctx, userID, "asset_registered", fmt.Sprintf("Registered asset %q", name), r.RemoteAddr, r.UserAgent())
		a.SendResponse(w, r, true, "Asset registered successfully", "/assets", "")
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (a *App) DeleteAssetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}
	idStr := r.FormValue("id")
	assetID, err := strconv.Atoi(idStr)
	if err != nil {
		a.SendResponse(w, r, false, "", "", "Invalid asset ID")
		return
	}
	commandTag, err := a.Pool.Exec(r.Context(), "DELETE FROM assets WHERE id = $1 AND (user_id = $2 OR team_id IN (SELECT team_id FROM team_members WHERE user_id = $2 AND role IN ('owner', 'admin')))", assetID, userID)
	if err != nil {
		a.SendResponse(w, r, false, "", "", "Error deleting asset")
		return
	}
	if commandTag.RowsAffected() == 0 {
		a.SendResponse(w, r, false, "", "", "Asset not found or access denied")
		return
	}

	a.LogActivity(r.Context(), userID, "asset_deleted", fmt.Sprintf("Deleted asset ID %d", assetID), r.RemoteAddr, r.UserAgent())
	a.SendResponse(w, r, true, "Asset removed successfully", "/assets", "")
}
