package web

import (
	"crypto/rand"
	"cve-tracker/internal/models"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
)

func (a *App) AdminUserManagementHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := a.Pool.Query(r.Context(), "SELECT id, email, is_email_verified, is_admin, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.IsEmailVerified, &u.IsAdmin, &u.CreatedAt); err != nil {
			log.Printf("Error scanning user row: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating user rows: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Generate a secure token for admin actions
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Printf("Error generating random CSRF token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(b)
	session.Values["admin_csrf_token"] = token
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving admin CSRF token: %v", err)
	}

	a.RenderTemplate(w, r, "admin_users.html", map[string]interface{}{
		"Users":     users,
		"CSRFToken": token,
	})
}

func (a *App) AdminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !a.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	idStr := r.FormValue("id")
	if idStr == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Prevent admin from deleting themselves
	currentUserID, ok := a.GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if id == currentUserID {
		http.Error(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}

	res, err := a.Pool.Exec(r.Context(), "DELETE FROM users WHERE id = $1 AND is_admin = FALSE", id)
	if err != nil {
		log.Printf("Failed to delete user %d: %v", id, err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	if res.RowsAffected() > 0 {
		a.LogActivity(r.Context(), currentUserID, "user_delete", "Deleted user ID "+strconv.Itoa(id), r.RemoteAddr, r.UserAgent())
	}

	if res.RowsAffected() == 0 {
		http.Error(w, "User not found or cannot be deleted", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusFound)
}
