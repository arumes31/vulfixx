package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) ListAssetsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	assets, err := a.AssetRepo.ListAssets(r.Context(), userID)
	if err != nil {
		slog.Error("Error fetching assets", "user_id", userID, "error", err)
		http.Error(w, "Error fetching assets", http.StatusInternalServerError)
		return
	}

	a.RenderTemplate(w, r, "assets.html", map[string]interface{}{"Assets": assets})
}

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

	name, assetType, priority, teamID, kwList, errMsg := a.parseAndValidateAssetForm(r)
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
			slog.Error("Error creating asset", "user_id", userID, "error", err)
			a.SendResponse(w, r, false, "", "", "Internal server error")
		}
		return
	}

	a.LogActivity(r.Context(), userID, "asset_registered", fmt.Sprintf("Registered asset %q", name), a.GetClientIP(r), r.UserAgent())
	a.SendResponse(w, r, true, "Asset registered successfully", "/assets", "")
}

func (a *App) parseAndValidateAssetForm(r *http.Request) (string, string, string, *int, []string, string) {
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
			return "", "", "", nil, nil, "Invalid team_id"
		}
		teamID = &tid
	}

	// Basic validation
	if len(name) < 1 || len(name) > 255 {
		return "", "", "", nil, nil, "Asset name must be between 1 and 255 characters"
	}

	allowedTypes := map[string]bool{
		"Server":   true,
		"Software": true,
		"Network":  true,
		"Cloud":    true,
		"IoT":      true,
	}
	if !allowedTypes[assetType] {
		return "", "", "", nil, nil, "Invalid asset category"
	}

	allowedPriorities := map[string]bool{"P0": true, "P1": true, "P2": true, "P3": true}
	if !allowedPriorities[priority] {
		return "", "", "", nil, nil, "Invalid priority level"
	}

	var kwList []string
	if keywords != "" {
		rawKws := strings.Split(keywords, ",")
		for _, kw := range rawKws {
			kw = strings.TrimSpace(kw)
			if kw != "" {
				if len(kw) > 50 {
					return "", "", "", nil, nil, "Keyword too long (maximum 50 characters)"
				}
				kwList = append(kwList, kw)
			}
		}
		if len(kwList) > 10 {
			return "", "", "", nil, nil, "Too many keywords (maximum 10)"
		}
	}

	return name, assetType, priority, teamID, kwList, ""
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

	rowsAffected, err := a.AssetRepo.DeleteAsset(r.Context(), assetID, userID)
	if err != nil {
		slog.Error("Error deleting asset", "user_id", userID, "asset_id", assetID, "error", err)
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
