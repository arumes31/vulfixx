package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// ListAssetsHandler renders the assets management page.
func (a *App) ListAssetsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	assets, err := a.AssetRepo.ListAssets(r.Context(), userID)
	if err != nil {
		log.Printf("Error fetching assets: %v", err)
		http.Error(w, "Error fetching assets", http.StatusInternalServerError)
		return
	}

	a.RenderTemplate(w, r, "assets.html", map[string]interface{}{"Assets": assets})
}

// CreateAssetHandler handles the registration of new assets.
func (a *App) CreateAssetHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}

	if err := r.ParseForm(); err != nil {
		a.SendResponse(w, r, false, "", "", "Error parsing form")
		return
	}

	name := r.FormValue("name")
	assetType := r.FormValue("type")
	priority := r.FormValue("priority")
	if priority == "" {
		priority = "P3"
	}
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
	}

	kwList, errMsg := a.validateAssetInput(name, assetType, priority, keywords)
	if errMsg != "" {
		a.SendResponse(w, r, false, "", "", errMsg)
		return
	}

	_, err := a.AssetRepo.CreateAsset(r.Context(), userID, teamID, name, assetType, priority, kwList)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "permission denied") {
			a.SendResponse(w, r, false, "", "", "You are not a member of this team")
		} else if strings.Contains(errMsg, "maximum of") {
			a.SendResponse(w, r, false, "", "", errMsg)
		} else {
			log.Printf("Error creating asset: %v", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
		}
		return
	}

	a.LogActivity(r.Context(), userID, "asset_registered", fmt.Sprintf("Registered asset %q", name), a.GetClientIP(r), r.UserAgent())
	a.SendResponse(w, r, true, "Asset registered successfully", "/assets", "")
}

// DeleteAssetHandler handles the removal of an existing asset.
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

	rowsAffected, err := a.AssetRepo.DeleteAsset(r.Context(), assetID, userID)
	if err != nil {
		log.Printf("Error deleting asset: %v", err)
		a.SendResponse(w, r, false, "", "", "Error deleting asset")
		return
	}

	if rowsAffected == 0 {
		a.SendResponse(w, r, false, "", "", "Asset not found or access denied")
		return
	}

	a.LogActivity(r.Context(), userID, "asset_deleted", fmt.Sprintf("Deleted asset ID %d", assetID), a.GetClientIP(r), r.UserAgent())
	a.SendResponse(w, r, true, "Asset removed successfully", "/assets", "")
}

func (a *App) validateAssetInput(name, assetType, priority, keywords string) ([]string, string) {
	if len(name) < 1 || len(name) > 255 {
		return nil, "Asset name must be between 1 and 255 characters"
	}

	allowedTypes := map[string]bool{
		"Server":   true,
		"Software": true,
		"Network":  true,
		"Cloud":    true,
		"IoT":      true,
	}
	if !allowedTypes[assetType] {
		return nil, "Invalid asset category"
	}

	allowedPriorities := map[string]bool{"P0": true, "P1": true, "P2": true, "P3": true}
	if !allowedPriorities[priority] {
		return nil, "Invalid priority level"
	}

	var kwList []string
	if keywords != "" {
		rawKws := strings.Split(keywords, ",")
		for _, kw := range rawKws {
			kw = strings.TrimSpace(kw)
			if kw != "" {
				if len(kw) > 50 {
					return nil, "Keyword too long (maximum 50 characters)"
				}
				kwList = append(kwList, kw)
			}
		}
		if len(kwList) > 10 {
			return nil, "Too many keywords (maximum 10)"
		}
	}

	return kwList, ""
}
