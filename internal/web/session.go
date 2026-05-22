package web

import (
	"context"
	"cve-tracker/internal/db"
	"errors"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/rbcervilla/redisstore/v9"
	"github.com/redis/go-redis/v9"
)

var store sessions.Store

func InitSession(key []byte, secure bool) sessions.Store {
	s := sessions.NewCookieStore(key)
	s.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	store = s // Keep global for now to avoid breaking everything at once
	return s
}

func InitRedisSession(client db.RedisProvider, key []byte, secure bool) (sessions.Store, error) {
	if client == nil {
		return nil, errors.New("redis client is nil")
	}
	rClient, ok := client.(redis.UniversalClient)
	if !ok {
		return nil, errors.New("invalid redis client type")
	}

	rs, err := redisstore.NewRedisStore(context.Background(), rClient)
	if err != nil {
		return nil, err
	}

	rs.KeyPrefix("vulfixx_session:")
	rs.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	store = rs
	return rs, nil
}

func GetSessionStore() sessions.Store {
	return store
}

func (a *App) GetUserID(r *http.Request) (int, bool) {
	if a.SessionStore == nil {
		return 0, false
	}
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	userID, ok := session.Values["user_id"].(int)
	return userID, ok
}

func (a *App) GetActiveTeamID(r *http.Request) (int, bool) {
	if a.SessionStore == nil {
		return 0, false
	}
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	teamID, ok := session.Values["team_id"].(int)
	return teamID, ok
}

func (a *App) SetActiveTeamID(w http.ResponseWriter, r *http.Request, teamID int) error {
	if a.SessionStore == nil {
		return errors.New("session store not initialized")
	}
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
	if a.SessionStore == nil {
		return false
	}
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return false
	}
	isAdmin, ok := session.Values["is_admin"].(bool)
	return ok && isAdmin
}
