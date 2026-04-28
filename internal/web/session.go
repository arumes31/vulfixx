package web

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

func InitSession() *sessions.CookieStore {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}

	key := os.Getenv("SESSION_KEY")
	if key == "" {
		if env != "development" {
			panic("SESSION_KEY environment variable is required in production. For local testing, set ENV=development or provide a SESSION_KEY")
		}
		key = "default-secret-key"
	}
	s := sessions.NewCookieStore([]byte(key))
	s.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   os.Getenv("SECURE_COOKIE") == "true",
		SameSite: http.SameSiteLaxMode,
	}
	store = s // Keep global for now to avoid breaking everything at once
	return s
}

func GetSessionStore() sessions.Store {
	return store
}

func (a *App) GetUserID(r *http.Request) (int, bool) {
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	userID, ok := session.Values["user_id"].(int)
	return userID, ok
}

func (a *App) GetActiveTeamID(r *http.Request) (int, bool) {
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	teamID, ok := session.Values["team_id"].(int)
	return teamID, ok
}

func (a *App) SetActiveTeamID(w http.ResponseWriter, r *http.Request, teamID int) error {
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		log.Printf("SetActiveTeamID error getting session: %v", err)
		return err
	}
	session.Values["team_id"] = teamID
	if err := session.Save(r, w); err != nil {
		log.Printf("SetActiveTeamID error saving session: %v", err)
		return err
	}
	return nil
}

func (a *App) IsAdmin(r *http.Request) bool {
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return false
	}
	isAdmin, ok := session.Values["is_admin"].(bool)
	return ok && isAdmin
}

// Global versions for compatibility during transition
func GetUserID(r *http.Request) (int, bool) {
	if store == nil {
		return 0, false
	}
	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	userID, ok := session.Values["user_id"].(int)
	return userID, ok
}

func GetActiveTeamID(r *http.Request) (int, bool) {
	if store == nil {
		return 0, false
	}
	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	teamID, ok := session.Values["team_id"].(int)
	return teamID, ok
}

func IsAdmin(r *http.Request) bool {
	if store == nil {
		return false
	}
	session, err := store.Get(r, "vulfixx-session")
	if err != nil {
		return false
	}
	isAdmin, ok := session.Values["is_admin"].(bool)
	return ok && isAdmin
}
