package web

import (
	"context"
	"cve-tracker/internal/db"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

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

func getSessionInt(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case int:
		return val, true
	case int32:
		return int(val), true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	case float32:
		return int(val), true
	}
	return 0, false
}

func getSessionInt64(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int32:
		return int64(val), true
	case int64:
		return val, true
	case float64:
		return int64(val), true
	case float32:
		return int64(val), true
	}
	return 0, false
}

func (a *App) GetActiveUserID(r *http.Request) (int, bool) {
	if a.SessionStore == nil {
		return 0, false
	}
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	return getSessionInt(session.Values["user_id"])
}

func (a *App) GetUserID(r *http.Request) (int, bool) {
	return a.GetActiveUserID(r)
}

func (a *App) GetActiveTeamID(r *http.Request) (int, bool) {
	if a.SessionStore == nil {
		return 0, false
	}
	session, err := a.SessionStore.Get(r, "vulfixx-session")
	if err != nil {
		return 0, false
	}
	return getSessionInt(session.Values["team_id"])
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

// EnforceConcurrentSessions caps a user's active concurrent sessions to 3, evicting the oldest session.
func (a *App) EnforceConcurrentSessions(ctx context.Context, userID int, sessionID string) {
	if a.Redis == nil || sessionID == "" {
		return
	}
	key := fmt.Sprintf("user_sessions:%d", userID)
	now := time.Now().Unix()

	// Add/update current session ID with timestamp score
	_, _ = a.Redis.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: sessionID}).Result()

	// Expire the user sessions ZSet key after 30 days of inactivity to prevent Redis memory leaks
	_, _ = a.Redis.Expire(ctx, key, 30*24*time.Hour).Result()

	// Get total session count
	count, err := a.Redis.ZCard(ctx, key).Result()
	if err != nil {
		return
	}

	maxSessions := 3
	if count > int64(maxSessions) {
		// Fetch oldest session IDs (from index 0 to count - maxSessions - 1)
		oldSessions, err := a.Redis.ZRange(ctx, key, 0, count-int64(maxSessions)-1).Result()
		if err == nil {
			for _, oldSessionID := range oldSessions {
				// Delete session key in Redis session prefix vulfixx_session:
				_, _ = a.Redis.Del(ctx, "vulfixx_session:"+oldSessionID).Result()
				// Remove from ZSet
				_, _ = a.Redis.ZRem(ctx, key, oldSessionID).Result()
			}
		}
	}
}
