package web

import (
	"cve-tracker/internal/db"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"github.com/gorilla/mux"
)

func TestWebEndpoints(t *testing.T) {
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "cveuser")
	os.Setenv("DB_PASSWORD", "cvepass")
	os.Setenv("DB_NAME", "cvetracker")
	os.Setenv("REDIS_URL", "localhost:6379")
	os.Setenv("SESSION_KEY", "supersecret")

	if err := db.InitDB(); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	if err := db.InitRedis(); err != nil {
		t.Fatalf("Failed to init Redis: %v", err)
	}
	defer db.CloseDB()
	defer db.CloseRedis()

	InitSession()

	// Need to be at project root or templates/ won't load
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}
	InitTemplates()

	r := mux.NewRouter()
	r.HandleFunc("/", IndexHandler).Methods("GET")
	r.HandleFunc("/login", LoginHandler).Methods("GET", "POST")
	r.HandleFunc("/register", RegisterHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")
	r.HandleFunc("/dashboard", DashboardHandler).Methods("GET")

	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("Failed GET /: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("Failed GET /login: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/register")
	if err != nil {
		t.Fatalf("Failed GET /register: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("Failed GET /dashboard: %v", err)
	}
	resp.Body.Close()
}

