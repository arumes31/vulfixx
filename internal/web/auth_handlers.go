package web

import (
	"cve-tracker/internal/auth"
	"cve-tracker/internal/db"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		RenderTemplate(w, r, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	totpCode := r.FormValue("totp_code")

	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check if this is a TOTP submission for a pre-authenticated user
	preAuthUserID, hasPreAuth := session.Values["pre_auth_user_id"].(int)

	if hasPreAuth && totpCode != "" {
		preAuthTS, _ := session.Values["pre_auth_ts"].(int64)
		attempts, _ := session.Values["pre_auth_attempts"].(int)

		if time.Now().Unix()-preAuthTS > 300 {
			delete(session.Values, "pre_auth_user_id")
			delete(session.Values, "pre_auth_ts")
			delete(session.Values, "pre_auth_attempts")
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Session expired"})
			return
		}

		if attempts >= 5 {
			delete(session.Values, "pre_auth_user_id")
			delete(session.Values, "pre_auth_ts")
			delete(session.Values, "pre_auth_attempts")
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
			return
		}

		var isTOTPEnabled bool
		var secret string
		err := db.Pool.QueryRow(r.Context(), "SELECT is_totp_enabled, COALESCE(totp_secret, '') FROM users WHERE id = $1", preAuthUserID).Scan(&isTOTPEnabled, &secret)
		if err != nil {
			log.Printf("DB error fetching TOTP secret: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !isTOTPEnabled || secret == "" {
			log.Printf("User %d in pre-auth but TOTP not enabled or secret missing", preAuthUserID)
			delete(session.Values, "pre_auth_user_id")
			delete(session.Values, "pre_auth_ts")
			delete(session.Values, "pre_auth_attempts")
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "2FA is not properly configured"})
			return
		}

		if !totp.Validate(totpCode, secret) {
			session.Values["pre_auth_attempts"] = attempts + 1
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			RenderTemplate(w, r, "login.html", map[string]interface{}{
				"Error":       "Invalid TOTP code",
				"RequireTOTP": true,
			})
			return
		}

		// Success! Clear pre-auth and set full auth
		delete(session.Values, "pre_auth_user_id")
		delete(session.Values, "pre_auth_ts")
		delete(session.Values, "pre_auth_attempts")
		session.Values["user_id"] = preAuthUserID

		var isAdmin bool
		err = db.Pool.QueryRow(r.Context(), "SELECT is_admin FROM users WHERE id = $1", preAuthUserID).Scan(&isAdmin)
		if err != nil {
			log.Printf("DB error fetching is_admin: %v", err)
		}
		session.Values["is_admin"] = isAdmin

		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		LogActivity(r.Context(), preAuthUserID, "login", "Successful 2FA login", r.RemoteAddr, r.UserAgent())
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	user, err := auth.Login(r.Context(), email, password)
	if err != nil {
		RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Invalid credentials"})
		return
	}

	if user.IsTOTPEnabled {
		session.Values["pre_auth_user_id"] = user.ID
		session.Values["pre_auth_ts"] = time.Now().Unix()
		session.Values["pre_auth_attempts"] = 0
		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		LogActivity(r.Context(), user.ID, "login_attempt", "Password correct, awaiting 2FA", r.RemoteAddr, r.UserAgent())

		RenderTemplate(w, r, "login.html", map[string]interface{}{
			"RequireTOTP": true,
		})
		return
	}

	session.Values["user_id"] = user.ID
	session.Values["is_admin"] = user.IsAdmin
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	LogActivity(r.Context(), user.ID, "login", "Successful login", r.RemoteAddr, r.UserAgent())

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		RenderTemplate(w, r, "register.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Invalid form"})
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")

	token, err := auth.Register(r.Context(), email, password)
	if err != nil {
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}

	// Push email verification payload to redis queue
	payload, err := json.Marshal(map[string]string{
		"email": email,
		"token": token,
	})
	if err != nil {
		log.Printf("Error marshaling verification payload: %v", err)
		// Rollback: delete the user we just created since we can't send verification
		if _, delErr := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			log.Printf("Error rolling back user creation for %q: %v", sanitizeForLog(redactEmail(email)), delErr)
		}
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	if err := db.RedisClient.LPush(r.Context(), "email_verification_queue", payload).Err(); err != nil {
		log.Printf("Error enqueueing verification payload: %v", err)
		// Rollback: delete the user we just created since we can't send verification
		if _, delErr := db.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			log.Printf("Error rolling back user creation for %q: %v", sanitizeForLog(redactEmail(email)), delErr)
		}
		RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	log.Printf("Verification queued for %q", sanitizeForLog(redactEmail(email)))

	RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Registration successful. Please check your email to verify your account."})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	err := auth.VerifyEmail(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email verified successfully! You can now login."})
}

func ConfirmEmailChangeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	confirmed, _, confirmedUserID, err := auth.ConfirmEmailChange(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	if confirmed {
		LogActivity(r.Context(), confirmedUserID, "email_change", "Successfully changed email", r.RemoteAddr, r.UserAgent())
		RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email changed successfully! Please login with your new email."})
	} else {
		RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email change half-confirmed. Please confirm on the other email address as well."})
	}
}

func redactEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "[invalid-email]"
	}
	if len(parts[0]) <= 2 {
		return "*@" + parts[1]
	}
	return parts[0][:2] + "****@" + parts[1]
}
