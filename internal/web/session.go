package web

import (
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

func InitSession() {
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
	store = sessions.NewCookieStore([]byte(key))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   os.Getenv("SECURE_COOKIE") == "true",
	}
}

func GetUserID(r *http.Request) (int, bool) {
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	return userID, ok
}
