package web

import (
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
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
			       COALESCE(array_agg(ak.keyword) FILTER (WHERE ak.keyword IS NOT NULL), '{}')
			FROM assets a
			LEFT JOIN asset_keywords ak ON a.id = ak.asset_id
			WHERE a.user_id = $1
			GROUP BY a.id
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
		}
		var assets []AssetWithKeywords
		for rows.Next() {
			var a AssetWithKeywords
			if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.CreatedAt, &a.Keywords); err != nil {
				continue
			}
			assets = append(assets, a)
		}
		RenderTemplate(w, r, "assets.html", map[string]interface{}{"Assets": assets})
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		assetType := r.FormValue("type")
		keywords := r.FormValue("keywords")

		// Validate inputs (Issue 5)
		if len(name) < 1 || len(name) > 255 {
			http.Error(w, "Asset name must be between 1 and 255 characters", http.StatusBadRequest)
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
			http.Error(w, "Invalid asset category", http.StatusBadRequest)
			return
		}

		tx, err := db.Pool.Begin(r.Context())
		if err != nil {
			http.Error(w, "Error starting transaction", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var assetID int
		err = tx.QueryRow(r.Context(), `
			INSERT INTO assets (user_id, name, type) VALUES ($1, $2, $3) RETURNING id
		`, userID, name, assetType).Scan(&assetID)
		if err != nil {
			http.Error(w, "Error creating asset", http.StatusInternalServerError)
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
						http.Error(w, "Error adding keyword", http.StatusInternalServerError)
						return
					}
				}
			}
		}

		if err = tx.Commit(r.Context()); err != nil {
			http.Error(w, "Error committing transaction", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/assets", http.StatusFound)
	}
}

func DeleteAssetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	idStr := r.FormValue("id")
	// Sanitize for logging (Issue 706)
	safeIdStr := strings.ReplaceAll(strings.ReplaceAll(idStr, "\n", ""), "\r", "")
	assetID, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("DeleteAsset: invalid asset ID %q: %v", safeIdStr, err)
		http.Error(w, "Invalid asset ID", http.StatusBadRequest)
		return
	}
	_, err = db.Pool.Exec(r.Context(), "DELETE FROM assets WHERE id = $1 AND user_id = $2", assetID, userID)
	if err != nil {
		http.Error(w, "Error deleting asset", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/assets", http.StatusFound)
}
