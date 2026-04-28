package web

import (
	"cve-tracker/internal/auth"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/pquerna/otp/totp"
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
	session.Values["totp_setup_ts"] = time.Now().Unix()
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

	if setupTS == 0 || time.Now().Unix()-setupTS > 600 {
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

	valid := totp.Validate(code, secret)
	if valid {
		if _, err := a.Pool.Exec(r.Context(), "UPDATE users SET is_totp_enabled = TRUE WHERE id = $1", userID); err != nil {
			log.Printf("Error enabling TOTP: %v", err)
		}
		delete(session.Values, "totp_setup_ts")
		delete(session.Values, "totp_setup_attempts")
		_ = session.Save(r, w)
	} else {
		session.Values["totp_setup_attempts"] = attempts + 1
		_ = session.Save(r, w)
		http.Redirect(w, r, "/settings?error=Invalid+TOTP+code", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings", http.StatusFound)
}

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
	var hash string
	var secret string
	err := a.Pool.QueryRow(r.Context(), "SELECT email, is_totp_enabled, password_hash, COALESCE(totp_secret, '') FROM users WHERE id = $1", userID).Scan(&email, &isTOTPEnabled, &hash, &secret)
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

	err = auth.ChangePassword(r.Context(), userID, currentPassword, newPassword, totpCode)
	if err != nil {
		renderError(err.Error())
		return
	}

	a.RenderTemplate(w, r, "settings.html", map[string]interface{}{
		"Email":           email,
		"IsTOTPEnabled":   isTOTPEnabled,
		"PasswordSuccess": "Password updated successfully.",
	})
}

func (a *App) ChangeEmailHandler(w http.ResponseWriter, r *http.Request) {
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

	// Push email change notification payloads to redis queue
	oldPayload, _ := json.Marshal(map[string]string{
		"email": email,
		"token": oldToken,
		"type":  "old",
	})
	newPayload, _ := json.Marshal(map[string]string{
		"email": newEmail,
		"token": newToken,
		"type":  "new",
	})
	// Push email change notification payloads to redis queue atomically
	pipe := a.Redis.Pipeline()
	pipe.LPush(r.Context(), "email_change_queue", oldPayload)
	pipe.LPush(r.Context(), "email_change_queue", newPayload)
	if _, err := pipe.Exec(r.Context()); err != nil {
		log.Printf("Error enqueueing email change payloads: %v", err)
		renderError("Error requesting email change")
		return
	}

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
