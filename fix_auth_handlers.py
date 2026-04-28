import os

with open('internal/web/auth_handlers.go', 'r') as f:
    content = f.read()

# Replace the 5 attempts check
old_attempts = """		if attempts >= 5 {
			delete(session.Values, "pre_auth_user_id")
			delete(session.Values, "pre_auth_ts")
			delete(session.Values, "pre_auth_attempts")
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
			return
		}"""

new_attempts = """		// Verify rate limit before checking TOTP
		rlKey := "totp_failures:" + r.RemoteAddr
		if count, err := a.Redis.Get(r.Context(), rlKey).Int(); err == nil && count >= 5 {
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
			return
		}"""

content = content.replace(old_attempts, new_attempts)

old_totp_fail = """		if !totp.Validate(totpCode, secret) {
			session.Values["pre_auth_attempts"] = attempts + 1
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{
				"Error":       "Invalid TOTP code",
				"RequireTOTP": true,
			})
			return
		}"""

new_totp_fail = """		if !totp.Validate(totpCode, secret) {
			a.Redis.Incr(r.Context(), rlKey)
			a.Redis.Expire(r.Context(), rlKey, 15*time.Minute)
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{
				"Error":       "Invalid TOTP code",
				"RequireTOTP": true,
			})
			return
		}
		// Clear rate limit on success
		a.Redis.Del(r.Context(), rlKey)"""

content = content.replace(old_totp_fail, new_totp_fail)

# Also check before accepting password re-entry
old_login_check = """	user, err := auth.Login(r.Context(), email, password)
	if err != nil {"""

new_login_check = """	rlKeyLogin := "totp_failures:" + r.RemoteAddr
	if count, err := a.Redis.Get(r.Context(), rlKeyLogin).Int(); err == nil && count >= 5 {
		a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
		return
	}

	user, err := auth.Login(r.Context(), email, password)
	if err != nil {"""

content = content.replace(old_login_check, new_login_check)

# Add GET check
old_get = """func (a *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.RenderTemplate(w, r, "login.html", nil)
		return
	}"""
new_get = """func (a *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rlKeyGet := "totp_failures:" + r.RemoteAddr
		if count, err := a.Redis.Get(r.Context(), rlKeyGet).Int(); err == nil && count >= 5 {
			a.RenderTemplate(w, r, "login.html", map[string]interface{}{"Error": "Too many attempts"})
			return
		}
		a.RenderTemplate(w, r, "login.html", nil)
		return
	}"""
content = content.replace(old_get, new_get)

with open('internal/web/auth_handlers.go', 'w') as f:
    f.write(content)
