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
	mock, _ := db.SetupTestDB()
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
		mr, _ := db.SetupTestRedis()
		defer mr.Close()
		app.Redis = db.RedisClient

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
		mr, _ := db.SetupTestRedis()
		defer mr.Close()
		app.Redis = db.RedisClient

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
		mock, _ := pgxmock.NewPool()
		defer mock.Close()
		mr, _ := miniredis.Run()
		defer mr.Close()
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

		app := &App{Pool: mock, Redis: rdb}
		mock.ExpectPing().WillReturnError(fmt.Errorf("db down"))

		req := httptest.NewRequest("GET", "/readyz", nil)
		rr := httptest.NewRecorder()

		app.ReadyzHandler(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", rr.Code)
		}
	})
}
