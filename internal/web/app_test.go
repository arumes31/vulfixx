package web

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/sessions"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/redis/go-redis/v9"
)

func TestNewApp(t *testing.T) {
	// Setup mocks
	mockPool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create mock pool: %v", err)
	}
	defer mockPool.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer redisClient.Close()

	sessionStore := sessions.NewCookieStore([]byte("secret"))
	mailer := &MockMailer{}

	// Call NewApp
	app := NewApp(mockPool, redisClient, sessionStore, mailer)

	// Verify fields
	if app.Pool != mockPool {
		t.Errorf("expected Pool to be %v, got %v", mockPool, app.Pool)
	}
	if app.Redis != redisClient {
		t.Errorf("expected Redis to be %v, got %v", redisClient, app.Redis)
	}
	if app.SessionStore != sessionStore {
		t.Errorf("expected SessionStore to be %v, got %v", sessionStore, app.SessionStore)
	}
	if app.Mailer != mailer {
		t.Errorf("expected Mailer to be %v, got %v", mailer, app.Mailer)
	}
	if app.TemplateMap == nil {
		t.Error("expected TemplateMap to be initialized, got nil")
	}
	if app.Now == nil {
		t.Error("expected Now to be initialized, got nil")
	}
	if app.AssetRepo == nil {
		t.Error("expected AssetRepo to be initialized, got nil")
	}
	if app.StatsInterval != 5*time.Minute {
		t.Errorf("expected StatsInterval to be 5m, got %v", app.StatsInterval)
	}
}
