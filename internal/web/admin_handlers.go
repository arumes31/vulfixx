package web

import (
	"crypto/rand"
	"crypto/subtle"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"time"
)

func AdminUserManagementHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Pool.Query(r.Context(), "SELECT id, email, is_email_verified, is_admin, created_at FROM users ORDER BY created_at DESC")
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
			continue
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating user rows: %v", err)
	}

	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("AdminUserManagementHandler: session get error: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	csrfToken, ok := session.Values["admin_csrf_token"].(string)
	if !ok || csrfToken == "" {
		b := make([]byte, 32)
		if _, randErr := rand.Read(b); randErr != nil {
			log.Printf("AdminUserManagementHandler: rand.Read error: %v", randErr)
			http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			return
		}
		csrfToken = hex.EncodeToString(b)
		session.Values["admin_csrf_token"] = csrfToken
		if saveErr := session.Save(r, w); saveErr != nil {
			log.Printf("AdminUserManagementHandler: session save error: %v", saveErr)
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}
	}

	RenderTemplate(w, r, "admin_users.html", map[string]interface{}{
		"Users":          users,
		"AdminCSRFToken": csrfToken,
	})
}

func AdminDeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	csrfToken := r.FormValue("csrf_token")
	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("AdminDeleteUserHandler: session get error: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	expectedToken, ok := session.Values["admin_csrf_token"].(string)
	if !ok || expectedToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(expectedToken)) != 1 {
		http.Error(w, "Forbidden: Invalid CSRF token", http.StatusForbidden)
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
	currentUserID, ok := GetUserID(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if id == currentUserID {
		http.Error(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}

	res, err := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE id = $1 AND is_admin = FALSE", id)
	if err != nil {
		log.Printf("Failed to delete user %d: %v", id, err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	if res.RowsAffected() > 0 {
		_, auditErr := db.Pool.Exec(r.Context(), 
			"INSERT INTO user_activity_logs (user_id, activity_type, description, ip_address, created_at) VALUES ($1, $2, $3, $4, $5)", 
			currentUserID, "user_delete", "Deleted user ID "+strconv.Itoa(id), r.RemoteAddr, time.Now())
		if auditErr != nil {
			log.Printf("Failed to insert audit log: %v", auditErr)
		}
	}

	if res.RowsAffected() == 0 {
		http.Error(w, "User not found or cannot be deleted", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusFound)
}
