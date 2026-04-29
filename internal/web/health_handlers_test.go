package web

import (
	"cve-tracker/internal/db"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestHealthHandlers(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()
	app := setupTestApp(t, mock)

	t.Run("HealthzHandler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		rr := httptest.NewRecorder()
		app.HealthzHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("ReadyzHandler_Success", func(t *testing.T) {
		mock.ExpectPing()
		_, err := db.SetupTestRedis()
		if err != nil {
			t.Fatalf("failed to setup redis: %v", err)
		}
		// setupTestApp already sets app.Redis to a local client
		// but let's be explicit and handle errors.
		
		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()
		app.ReadyzHandler(rr, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("ReadyzHandler_DBDown", func(t *testing.T) {
		mock.ExpectPing().WillReturnError(errors.New("db down"))
		_, err := db.SetupTestRedis()
		if err != nil {
			t.Fatalf("failed to setup redis: %v", err)
		}

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()
		app.ReadyzHandler(rr, req)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 Service Unavailable, got %d", rr.Code)
		}
	})

	t.Run("Readyz_V2_Failure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatalf("failed to create mock pool: %v", err)
		}
		defer mock.Close()
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to start miniredis: %v", err)
		}
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		defer func() { _ = rdb.Close() }()

		app := &App{Pool: mock, Redis: rdb}
		mock.ExpectPing().WillReturnError(fmt.Errorf("db down"))

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()

		app.ReadyzHandler(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", rr.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
