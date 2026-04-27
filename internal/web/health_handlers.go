package web

import (
	"encoding/json"
	"net/http"
)

// HealthzHandler returns a simple 200 OK to indicate the service is running.
func (a *App) HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// ReadyzHandler checks the database and redis connectivity.
func (a *App) ReadyzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]string{
		"database": "up",
		"redis":    "up",
	}

	isDown := false

	// Check DB
	if err := a.Pool.Ping(r.Context()); err != nil {
		status["database"] = "down"
		isDown = true
	}

	// Check Redis
	if err := a.Redis.Ping(r.Context()).Err(); err != nil {
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
