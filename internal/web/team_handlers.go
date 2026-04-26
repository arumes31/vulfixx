package web

import (
	"crypto/rand"
	"cve-tracker/internal/db"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

func generateInviteCode() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TeamsHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := GetUserID(r)

	rows, err := db.Pool.Query(r.Context(), `
		SELECT t.id, t.name, t.invite_code, tm.role 
		FROM teams t
		JOIN team_members tm ON t.id = tm.team_id
		WHERE tm.user_id = $1
		ORDER BY t.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("TeamsHandler DB Error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var teams []map[string]interface{}
	for rows.Next() {
		var id int
		var name, inviteCode, role string
		if err := rows.Scan(&id, &name, &inviteCode, &role); err == nil {
			teams = append(teams, map[string]interface{}{
				"ID":         id,
				"Name":       name,
				"InviteCode": inviteCode,
				"Role":       role,
			})
		}
	}

	RenderTemplate(w, r, "teams.html", map[string]interface{}{
		"Teams": teams,
	})
}

func CreateTeamHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.Redirect(w, r, "/teams", http.StatusFound)
		return
	}

	userID, _ := GetUserID(r)
	name := r.FormValue("name")
	if name == "" {
		SendResponse(w, r, false, "", "", "Team name is required")
		return
	}

	inviteCode := generateInviteCode()

	tx, err := db.Pool.Begin(r.Context())
	if err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var teamID int
	err = tx.QueryRow(r.Context(), "INSERT INTO teams (name, invite_code) VALUES ($1, $2) RETURNING id", name, inviteCode).Scan(&teamID)
	if err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	_, err = tx.Exec(r.Context(), "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'owner')", teamID, userID)
	if err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	LogActivity(r.Context(), userID, "team_created", fmt.Sprintf("Created team %q", name), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Team created successfully", "/teams", "")
}

func JoinTeamHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.Redirect(w, r, "/teams", http.StatusFound)
		return
	}

	userID, _ := GetUserID(r)
	inviteCode := r.FormValue("invite_code")
	if inviteCode == "" {
		SendResponse(w, r, false, "", "", "Invite code is required")
		return
	}

	var teamID int
	err := db.Pool.QueryRow(r.Context(), "SELECT id FROM teams WHERE invite_code = $1", inviteCode).Scan(&teamID)
	if err != nil {
		SendResponse(w, r, false, "", "", "Invalid invite code")
		return
	}

	_, err = db.Pool.Exec(r.Context(), "INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING", teamID, userID)
	if err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	LogActivity(r.Context(), userID, "team_joined", fmt.Sprintf("Joined team ID %d", teamID), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Joined workspace successfully", "/teams", "")
}

func LeaveTeamHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}

	userID, _ := GetUserID(r)
	teamIDStr := r.FormValue("team_id")
	teamID, _ := strconv.Atoi(teamIDStr)

	_, err := db.Pool.Exec(r.Context(), "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2", teamID, userID)
	if err != nil {
		SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	// Reset active team if it was the one left
	activeID, _ := GetActiveTeamID(r)
	if activeID == teamID {
		SetActiveTeamID(w, r, 0)
	}

	LogActivity(r.Context(), userID, "team_left", fmt.Sprintf("Left team ID %d", teamID), r.RemoteAddr, r.UserAgent())
	SendResponse(w, r, true, "Left workspace", "/teams", "")
}

func SwitchTeamHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _ := GetUserID(r)
	teamIDStr := r.FormValue("team_id")
	teamID, _ := strconv.Atoi(teamIDStr)

	if teamID != 0 {
		var exists bool
		err := db.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2)", teamID, userID).Scan(&exists)
		if err != nil || !exists {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	SetActiveTeamID(w, r, teamID)
	http.Redirect(w, r, r.Referer(), http.StatusFound)
}
