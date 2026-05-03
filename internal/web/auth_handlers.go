package web

import (
	"crypto/rand"
	"cve-tracker/internal/auth"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/pquerna/otp/totp"
)

func (a *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := a.GetClientIP(r)
	if r.Method == http.MethodGet {
		rlKeyGet := "totp_failures:" + clientIP
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
		rlKey := "login_failures:" + clientIP
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
		a.LogActivity(r.Context(), preAuthUserID, "login", "Successful 2FA login", a.GetClientIP(r), r.UserAgent())
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	rlKeyLogin := "login_failures:" + clientIP
	if count, err := a.Redis.Get(r.Context(), rlKeyLogin).Int(); err == nil && count >= 5 {
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
		return
	}

	user, err := auth.Login(r.Context(), email, password)
	if err != nil {
		a.Redis.Incr(r.Context(), rlKeyLogin)
		a.Redis.Expire(r.Context(), rlKeyLogin, 15*time.Minute)
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
		a.LogActivity(r.Context(), user.ID, "login_attempt", "Password correct, awaiting 2FA", clientIP, r.UserAgent())

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
	a.LogActivity(r.Context(), user.ID, "login", "Successful login", clientIP, r.UserAgent())

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

	// IP-based rate limit for registration: 5 attempts per hour
	clientIP := a.GetClientIP(r)
	rlKey := "reg_limit:" + clientIP
	if count, err := a.Redis.Get(r.Context(), rlKey).Int(); err == nil && count >= 5 {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Too many registration attempts. Please try again in an hour."})
		return
	}

	if err := r.ParseForm(); err != nil {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Invalid form"})
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")
	captchaAnswer := r.FormValue("captcha")

	if password != passwordConfirm {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Passwords do not match"})
		return
	}

	session, _ := a.SessionStore.Get(r, "vulfixx-session")
	expected, _ := session.Values["captcha_answer"].(int)
	actual, _ := strconv.Atoi(captchaAnswer)

	if expected == 0 || actual != expected {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Invalid captcha answer"})
		return
	}
	// Clear captcha after use
	delete(session.Values, "captcha_answer")
	_ = session.Save(r, w)

	token, err := auth.Register(r.Context(), email, password)
	if err != nil {
		a.RenderTemplate(w, r, "register.html", map[string]interface{}{"Error": "Registration failed"})
		return
	}

	// Increment IP rate limit
	a.Redis.Incr(r.Context(), rlKey)
	a.Redis.Expire(r.Context(), rlKey, 1*time.Hour)

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

func (a *App) ResendVerificationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.RenderTemplate(w, r, "resend_verification.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// IP-based rate limit: 5 attempts per hour
	clientIP := a.GetClientIP(r)
	rlKey := "resend_limit:" + clientIP
	if count, err := a.Redis.Get(r.Context(), rlKey).Int(); err == nil && count >= 5 {
		log.Printf("IP rate limit hit for resend: %s", clientIP)
		a.RenderTemplate(w, r, "resend_verification.html", map[string]interface{}{"Error": "Too many resend attempts. Please try again in an hour."})
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	captchaAnswer := r.FormValue("captcha")

	session, _ := a.SessionStore.Get(r, "vulfixx-session")
	expected, _ := session.Values["captcha_answer"].(int)
	actual, _ := strconv.Atoi(captchaAnswer)

	if expected == 0 || actual != expected {
		a.RenderTemplate(w, r, "resend_verification.html", map[string]interface{}{"Error": "Invalid captcha answer", "Email": email})
		return
	}
	delete(session.Values, "captcha_answer")
	_ = session.Save(r, w)

	// Per-email rate limit: 3 attempts per 30 mins
	emailRlKey := "resend_email_limit:" + email
	if count, err := a.Redis.Get(r.Context(), emailRlKey).Int(); err == nil && count >= 3 {
		log.Printf("Email rate limit hit for resend: %s", redactEmail(email))
		// Use generic message to prevent enumeration
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "If this email is registered and unverified, a new verification link will be sent."})
		return
	}

	token, err := auth.ResendVerificationToken(r.Context(), email)
	if err != nil {
		// Log the real error but show generic message
		log.Printf("Error resending verification for %q: %v", redactEmail(email), err)
		a.RenderTemplate(w, r, "resend_verification.html", map[string]interface{}{"Error": "Unable to resend verification email, please try again", "Email": email})
		return
	}

	// Increment rate limits
	a.Redis.Incr(r.Context(), rlKey)
	a.Redis.Expire(r.Context(), rlKey, 1*time.Hour)
	a.Redis.Incr(r.Context(), emailRlKey)
	a.Redis.Expire(r.Context(), emailRlKey, 30*time.Minute)

	// Push to queue
	payload, err := json.Marshal(map[string]string{
		"email": email,
		"token": token,
	})
	if err != nil {
		log.Printf("Error marshaling verification payload: %v", err)
		_ = auth.RollbackResend(r.Context(), email)
		a.RenderTemplate(w, r, "resend_verification.html", map[string]interface{}{"Error": "Unable to resend verification email, please try again", "Email": email})
		return
	}

	if err := a.Redis.LPush(r.Context(), "email_verification_queue", payload).Err(); err != nil {
		log.Printf("Error enqueueing verification payload: %v", err)
		_ = auth.RollbackResend(r.Context(), email)
		a.RenderTemplate(w, r, "resend_verification.html", map[string]interface{}{"Error": "Unable to resend verification email, please try again", "Email": email})
		return
	}

	a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "If this email is registered and unverified, a new verification link will be sent."})
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
		a.LogActivity(r.Context(), confirmedUserID, "email_change", "Successfully changed email", a.GetClientIP(r), r.UserAgent())
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email changed successfully! Please login with your new email."})
	} else {
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Message": "Email change half-confirmed. Please confirm on the other email address as well."})
	}
}

func (a *App) CaptchaHandler(w http.ResponseWriter, r *http.Request) {
	n1, _ := rand.Int(rand.Reader, big.NewInt(9))
	n2, _ := rand.Int(rand.Reader, big.NewInt(9))
	v1 := int(n1.Int64()) + 1
	v2 := int(n2.Int64()) + 1

	if os.Getenv("GO_ENV") == "test" {
		v1 = 5
		v2 = 5
	}

	sum := v1 + v2

	session, _ := a.SessionStore.Get(r, "vulfixx-session")
	session.Values["captcha_answer"] = sum
	_ = session.Save(r, w)

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// Generate a simple SVG with some noise
	svg := fmt.Sprintf(`
		<svg width="120" height="40" xmlns="http://www.w3.org/2000/svg">
			<rect width="100%%" height="100%%" fill="#1a1a1a" rx="8" />
			<text x="50%%" y="55%%" dominant-baseline="middle" text-anchor="middle" font-family="monospace" font-weight="bold" font-size="18" fill="#00f2fe">
				%d + %d = ?
			</text>
			<!-- Noise -->
			<line x1="10" y1="20" x2="110" y2="15" stroke="#ffffff11" stroke-width="1" />
			<line x1="20" y1="30" x2="100" y2="10" stroke="#ffffff11" stroke-width="1" />
			<circle cx="20" cy="10" r="1" fill="#ffffff22" />
			<circle cx="80" cy="30" r="1" fill="#ffffff22" />
			<circle cx="50" cy="35" r="1" fill="#ffffff22" />
		</svg>
	`, v1, v2)

	_, _ = w.Write([]byte(strings.TrimSpace(svg)))
}

func (a *App) CompleteOnboardingHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		a.SendResponse(w, r, false, "", "", "Unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		a.SendResponse(w, r, false, "", "", "Method not allowed")
		return
	}

	_, err := a.Pool.Exec(r.Context(), "UPDATE users SET onboarding_completed = TRUE WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error completing onboarding: %v", err)
		a.SendResponse(w, r, false, "", "", "Internal server error")
		return
	}

	a.SendResponse(w, r, true, "Welcome to Vulfixx!", "", "")
}

func (a *App) ErrorReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	// Limit request body to 8KB
	r.Body = http.MaxBytesReader(w, r.Body, 8192)

	type FrontendError struct {
		Message   string `json:"message"`
		Type      string `json:"type"`
		URL       string `json:"url"`
		Stack     string `json:"stack"`
		UserAgent string `json:"userAgent"`
	}

	var req FrontendError
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}

	// Truncate fields to safe lengths
	truncate := func(s string, limit int) string {
		if len(s) > limit {
			return s[:limit] + "..."
		}
		return s
	}

	msg := truncate(sanitizeForLog(req.Message), 1000)
	errType := truncate(sanitizeForLog(req.Type), 100)
	url := truncate(sanitizeForLog(req.URL), 500)

	log.Printf("FRONTEND ERROR: [%s] %s at %s", errType, msg, url)
	sentry.CaptureMessage(fmt.Sprintf("Frontend Error: %s", msg))
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
