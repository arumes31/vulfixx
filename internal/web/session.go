package web

import (
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

func InitSession() {
	key := os.Getenv("SESSION_KEY")
	if key == "" {
		if os.Getenv("ENV") != "development" {
			panic("SESSION_KEY environment variable is required in production")
		}
		key = "default-secret-key"
	}
	store = sessions.NewCookieStore([]byte(key))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   os.Getenv("ENV") != "development", // Set to true in prod with HTTPS
	}
}

func GetUserID(r *http.Request) (int, bool) {
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	return userID, ok
}
