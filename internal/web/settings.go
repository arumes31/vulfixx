package web

import (
	"cve-tracker/internal/auth"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/hibiken/asynq"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"rsc.io/qr"
)

func (a *App) SettingsHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var email string
	var isTOTPEnabled bool
	err := a.Pool.QueryRow(r.Context(), "SELECT email, is_totp_enabled FROM users WHERE id = $1", userID).Scan(&email, &isTOTPEnabled)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
		"Email":         email,
		"IsTOTPEnabled": isTOTPEnabled,
	})
}

func (a *App) GenerateTOTPHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var email string
	if err := a.Pool.QueryRow(r.Context(), "SELECT email FROM users WHERE id = $1", userID).Scan(&email); err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "CVETacker",
		AccountName: email,
	})
	if err != nil {
		http.Error(w, "Error generating TOTP", http.StatusInternalServerError)
		return
	}

	// Save secret to db
	_, err = a.Pool.Exec(r.Context(), "UPDATE users SET totp_secret = $1 WHERE id = $2", key.Secret(), userID)
	if err != nil {
		http.Error(w, "Error saving TOTP secret", http.StatusInternalServerError)
		return
	}

	session, _ := a.SessionStore.Get(r, "vulfixx-session")
	session.Values["totp_setup_ts"] = a.Now().Unix()
	session.Values["totp_setup_attempts"] = 0
	_ = session.Save(r, w)

	// Generate QR
	code, err := qr.Encode(key.URL(), qr.M)
	if err != nil {
		http.Error(w, "Error generating QR", http.StatusInternalServerError)
		return
	}

	qrBase64 := base64.StdEncoding.EncodeToString(code.PNG())

	a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
		"Email":         email,
		"IsTOTPEnabled": false,
		"QRBase64":      qrBase64,
		"Secret":        key.Secret(),
	})
}

func (a *App) VerifyTOTPHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}
	code := r.FormValue("totp_code")

	var secret string
	err := a.Pool.QueryRow(r.Context(), "SELECT totp_secret FROM users WHERE id = $1", userID).Scan(&secret)
	if err != nil || secret == "" {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}

	session, _ := a.SessionStore.Get(r, "vulfixx-session")
	setupTS, _ := session.Values["totp_setup_ts"].(int64)
	attempts, _ := session.Values["totp_setup_attempts"].(int)

	if setupTS == 0 || a.Now().Unix()-setupTS > 600 {
		delete(session.Values, "totp_setup_ts")
		delete(session.Values, "totp_setup_attempts")
		_ = session.Save(r, w)
		_, _ = a.Pool.Exec(r.Context(), "UPDATE users SET totp_secret = NULL WHERE id = $1 AND is_totp_enabled = FALSE", userID)
		http.Redirect(w, r, "/settings?error=Setup+expired+or+invalid", http.StatusFound)
		return
	}

	if attempts >= 5 {
		delete(session.Values, "totp_setup_ts")
		delete(session.Values, "totp_setup_attempts")
		_ = session.Save(r, w)
		_, _ = a.Pool.Exec(r.Context(), "UPDATE users SET totp_secret = NULL WHERE id = $1 AND is_totp_enabled = FALSE", userID)
		http.Redirect(w, r, "/settings?error=Too+many+attempts", http.StatusFound)
		return
	}

	valid, err := totp.ValidateCustom(code, secret, a.Now(), totp.ValidateOpts{
		Period: 30,
		Skew:   1,
		Digits: 6,
	})
	if err != nil {
		log.Printf("Error validating TOTP code: %v", err)
		http.Redirect(w, r, "/settings?error=Invalid+TOTP+code", http.StatusFound)
		return
	}
	if valid {
		if _, err := a.Pool.Exec(r.Context(), "UPDATE users SET is_totp_enabled = TRUE WHERE id = $1", userID); err != nil {
			log.Printf("Error enabling TOTP: %v", err)
			_ = session.Save(r, w)
			http.Redirect(w, r, "/settings?error=Failed+to+enable+2FA", http.StatusFound)
			return
		}
		delete(session.Values, "totp_setup_ts")
		delete(session.Values, "totp_setup_attempts")
		session.Values["totp_verified"] = true
		_ = session.Save(r, w)
		a.LogActivity(r.Context(), userID, "totp_enabled", "Successfully enabled 2FA", a.GetClientIP(r), r.UserAgent())
	} else {
		session.Values["totp_setup_attempts"] = attempts + 1
		_ = session.Save(r, w)
		http.Redirect(w, r, "/settings?error=Invalid+TOTP+code", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings", http.StatusFound)
}

// ChangePasswordHandler handles changing user passwords.
// @Summary Change User Password
// @Description Update the password of the authenticated user.
// @Tags Settings
// @Accept x-www-form-urlencoded
// @Produce html
// @Param current_password formData string true "Current Password"
// @Param new_password formData string true "New Password"
// @Param confirm_password formData string true "Confirm New Password"
// @Param totp_code formData string false "TOTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad Request"
// @Router /settings/password [post]
func (a *App) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	totpCode := r.FormValue("totp_code")

	var email string
	var isTOTPEnabled bool
	err := a.Pool.QueryRow(r.Context(), "SELECT email, is_totp_enabled FROM users WHERE id = $1", userID).Scan(&email, &isTOTPEnabled)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	renderError := func(msg string) {
		a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
			"Email":         email,
			"IsTOTPEnabled": isTOTPEnabled,
			"PasswordError": msg,
		})
	}

	if newPassword != confirmPassword {
		renderError("New passwords do not match")
		return
	}

	reqVal := ChangePasswordRequest{
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
		ConfirmPassword: confirmPassword,
		TOTPCode:        totpCode,
	}
	if err := Validate.Struct(reqVal); err != nil {
		renderError("New password must be at least 8 characters.")
		return
	}

	err = auth.ChangePassword(r.Context(), userID, currentPassword, newPassword, totpCode)
	if err != nil {
		errMsg := err.Error()
		// Map known errors to safe user-facing messages; log unknown ones
		switch {
		case strings.Contains(errMsg, "current password"):
			renderError("Current password is incorrect")
		case strings.Contains(errMsg, "too short") || strings.Contains(errMsg, "at least"):
			renderError("New password is too short (minimum 8 characters)")
		case strings.Contains(errMsg, "TOTP") || strings.Contains(errMsg, "totp"):
			renderError("Invalid or missing 2FA code")
		default:
			// #nosec G706 -- the %q format specifier automatically escapes control characters, making log injection impossible
			log.Printf("ChangePassword unexpected error for user %d: %q", userID, err.Error())
			renderError("Unable to change password. Please try again later.")
		}
		return
	}

	a.LogActivity(r.Context(), userID, "password_changed", "Successfully updated account password", a.GetClientIP(r), r.UserAgent())

	a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
		"Email":           email,
		"IsTOTPEnabled":   isTOTPEnabled,
		"PasswordSuccess": "Password updated successfully.",
	})
}

// ChangeEmailHandler handles user request to change email.
// @Summary Change User Email
// @Description Initiate a request to change the authenticated user's email address.
// @Tags Settings
// @Accept x-www-form-urlencoded
// @Produce html
// @Param new_email formData string true "New Email Address"
// @Param password formData string true "Current Password"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad Request"
// @Router /settings/email [post]
func (a *App) ChangeEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}

	newEmail := r.FormValue("new_email")
	password := r.FormValue("password")

	var email string
	var isTOTPEnabled bool
	if err := a.Pool.QueryRow(r.Context(), "SELECT email, is_totp_enabled FROM users WHERE id = $1", userID).Scan(&email, &isTOTPEnabled); err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	renderError := func(msg string) {
		a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
			"Email":         email,
			"IsTOTPEnabled": isTOTPEnabled,
			"EmailError":    msg,
		})
	}

	reqVal := ChangeEmailRequest{
		NewEmail: newEmail,
		Password: password,
	}
	if err := Validate.Struct(reqVal); err != nil {
		renderError("Invalid email format or empty password field.")
		return
	}

	// Verify password
	_, err := auth.Login(r.Context(), email, password)
	if err != nil {
		renderError("Invalid password")
		return
	}

	oldToken, newToken, err := auth.RequestEmailChange(r.Context(), userID, newEmail)
	if err != nil {
		renderError("Error requesting email change")
		return
	}

	// Push email change notification payloads to redis queue atomically as a single work item
	combinedPayload, _ := json.Marshal(map[string]string{
		"old_email": email,
		"old_token": oldToken,
		"new_email": newEmail,
		"new_token": newToken,
	})

	var enqueueErr error
	if a.AsynqClient != nil {
		task := asynq.NewTask("task:email_change", combinedPayload)
		_, enqueueErr = a.AsynqClient.EnqueueContext(r.Context(), task)
	} else {
		if a.Redis == nil {
			enqueueErr = errors.New("redis client is nil")
		} else {
			_, enqueueErr = a.Redis.TxPipelined(r.Context(), func(pipe redis.Pipeliner) error {
				pipe.LPush(r.Context(), "email_change_queue", combinedPayload)
				return nil
			})
		}
	}

	if enqueueErr != nil {
		log.Printf("Error enqueueing email change payloads: %v", enqueueErr)
		renderError("Error requesting email change")
		return
	}

	a.LogActivity(r.Context(), userID, "email_change_requested", "Email change requested", a.GetClientIP(r), r.UserAgent())

	a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
		"Email":         email,
		"IsTOTPEnabled": isTOTPEnabled,
		"EmailSuccess":  "Email change requested. Please confirm on BOTH your old and new email addresses.",
	})
}

func (a *App) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.GetUserID(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.Method != "POST" {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}

	password := r.FormValue("password")

	var email string
	if err := a.Pool.QueryRow(r.Context(), "SELECT email FROM users WHERE id = $1", userID).Scan(&email); err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Verify password
	_, err := auth.Login(r.Context(), email, password)
	if err != nil {
		a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
			"Email":       email,
			"DeleteError": "Invalid password",
		})
		return
	}

	// Delete user
	_, err = a.Pool.Exec(r.Context(), "DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		http.Error(w, "Error deleting account", http.StatusInternalServerError)
		return
	}

	// Clear session
	session, _ := a.SessionStore.Get(r, "vulfixx-session")
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
	}

	http.Redirect(w, r, "/register", http.StatusFound)
}
