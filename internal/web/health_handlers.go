package web

import (
	"cve-tracker/internal/db"
	"encoding/json"
	"net/http"
)

// HealthzHandler returns a simple 200 OK to indicate the service is running.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// ReadyzHandler checks the database and redis connectivity.
func ReadyzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	status := map[string]string{
		"database": "up",
		"redis":    "up",
	}
	
	isDown := false

	// Check DB
	if err := db.Pool.Ping(r.Context()); err != nil {
		status["database"] = "down"
		isDown = true
	}
	
	// Check Redis
	if err := db.RedisClient.Ping(r.Context()).Err(); err != nil {
		status["redis"] = "down"
		isDown = true
	}
	
	if isDown {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(status)
}
