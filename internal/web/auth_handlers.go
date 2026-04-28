package web

import (
	"cve-tracker/internal/auth"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func (a *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rlKeyGet := "totp_failures:" + r.RemoteAddr
		if count, err := a.Redis.Get(r.Context(), rlKeyGet).Int(); err == nil && count >= 5 {
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
			return
		}
		a.RenderTemplate(w, r, "login.html", nil)
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

	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check if this is a TOTP submission for a pre-authenticated user
	preAuthUserID, hasPreAuth := session.Values["pre_auth_user_id"].(int)

	if hasPreAuth && totpCode != "" {
		preAuthTS, _ := session.Values["pre_auth_ts"].(int64)

		if time.Now().Unix()-preAuthTS > 300 {
			delete(session.Values, "pre_auth_user_id")
			delete(session.Values, "pre_auth_ts")
			delete(session.Values, "pre_auth_attempts")
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Session expired"})
			return
		}

		// Verify rate limit before checking TOTP
		rlKey := "totp_failures:" + r.RemoteAddr
		if count, err := a.Redis.Get(r.Context(), rlKey).Int(); err == nil && count >= 5 {
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
			return
		}

		var isTOTPEnabled bool
		var secret string
		err := a.Pool.QueryRow(r.Context(), "SELECT is_totp_enabled, COALESCE(totp_secret, '') FROM users WHERE id = $1", preAuthUserID).Scan(&isTOTPEnabled, &secret)
		if err != nil {
			log.Printf("DB error fetching TOTP secret: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !isTOTPEnabled || secret == "" {
			// #nosec G706 -- preAuthUserID is an integer
			log.Printf("User %d in pre-auth but TOTP not enabled or secret missing", preAuthUserID)
			delete(session.Values, "pre_auth_user_id")
			delete(session.Values, "pre_auth_ts")
			delete(session.Values, "pre_auth_attempts")
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "2FA is not properly configured"})
			return
		}

		if !totp.Validate(totpCode, secret) {
			a.Redis.Incr(r.Context(), rlKey)
			a.Redis.Expire(r.Context(), rlKey, 15*time.Minute)
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{
				"Error":       "Invalid TOTP code",
				"RequireTOTP": true,
			})
			return
		}
		// Clear rate limit on success
		a.Redis.Del(r.Context(), rlKey)

		// Success! Clear pre-auth and set full auth
		delete(session.Values, "pre_auth_user_id")
		delete(session.Values, "pre_auth_ts")
		delete(session.Values, "pre_auth_attempts")
		session.Values["user_id"] = preAuthUserID

		var isAdmin bool
		err = a.Pool.QueryRow(r.Context(), "SELECT is_admin FROM users WHERE id = $1", preAuthUserID).Scan(&isAdmin)
		if err != nil {
			log.Printf("DB error fetching is_admin: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		session.Values["is_admin"] = isAdmin

		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		a.LogActivity(r.Context(), preAuthUserID, "login", "Successful 2FA login", r.RemoteAddr, r.UserAgent())
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	rlKeyLogin := "totp_failures:" + r.RemoteAddr
	if count, err := a.Redis.Get(r.Context(), rlKeyLogin).Int(); err == nil && count >= 5 {
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
		return
	}

	user, err := auth.Login(r.Context(), email, password)
	if err != nil {
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Invalid credentials"})
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
		a.LogActivity(r.Context(), user.ID, "login_attempt", "Password correct, awaiting 2FA", r.RemoteAddr, r.UserAgent())

		a.RenderTemplate(w, r, "login.html", map[string]interface{}{
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
	a.LogActivity(r.Context(), user.ID, "login", "Successful login", r.RemoteAddr, r.UserAgent())

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (a *App) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.RenderTemplate(w, r, "register.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Invalid form"})
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")

	token, err := auth.Register(r.Context(), email, password)
	if err != nil {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
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
		if _, delErr := a.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			// #nosec G706 -- sanitized via sanitizeForLog and redactEmail
			log.Printf("Error rolling back user creation for %q: %v", sanitizeForLog(redactEmail(email)), delErr)
		}
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	if err := a.Redis.LPush(r.Context(), "email_verification_queue", payload).Err(); err != nil {
		log.Printf("Error enqueueing verification payload: %v", err)
		// Rollback: delete the user we just created since we can't send verification
		if _, delErr := a.Pool.Exec(r.Context(), "DELETE FROM users WHERE email = $1", email); delErr != nil {
			// #nosec G706 -- sanitized via sanitizeForLog and redactEmail
			log.Printf("Error rolling back user creation for %q: %v", sanitizeForLog(redactEmail(email)), delErr)
		}
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}
	// #nosec G706 -- sanitized via sanitizeForLog and redactEmail
	log.Printf("Verification queued for %q", sanitizeForLog(redactEmail(email)))

	a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Registration successful. Please check your email to verify your account."})
}

func (a *App) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, err := a.SessionStore.Get(r, "vulfixx-session")
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

func (a *App) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
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

	a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email verified successfully! You can now login."})
}

func (a *App) ConfirmEmailChangeHandler(w http.ResponseWriter, r *http.Request) {
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
		a.LogActivity(r.Context(), confirmedUserID, "email_change", "Successfully changed email", r.RemoteAddr, r.UserAgent())
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email changed successfully! Please login with your new email."})
	} else {
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email change half-confirmed. Please confirm on the other email address as well."})
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
