package auth

import (
	"context"
	"cve-tracker/internal/db"
	"os"
	"strings"
	"testing"
)

func TestAuthIntegration(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping integration test in CI")
	}

	// Setup DB
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_USER", "cveuser")
	t.Setenv("DB_PASSWORD", "cvepass")
	t.Setenv("DB_NAME", "cvetracker")

	err := db.InitDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "timeout") {
			t.Skipf("skipping integration test: DB not available: %v", err)
		}
		t.Fatalf("Failed to init db: %v", err)
	}
	defer db.CloseDB()

	ctx := context.Background()

	// Clean up table for test
	_, _ = db.Pool.Exec(ctx, "DELETE FROM users WHERE email = 'test@example.com'")

	token, err := Register(ctx, "test@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	err = VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("Failed to verify email: %v", err)
	}

	user, err := Login(ctx, "test@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", user.Email)
	}

	err = ChangePassword(ctx, user.ID, "password", "newpassword", "")
	if err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}

	_, err = Login(ctx, "test@example.com", "newpassword")
	if err != nil {
		t.Fatalf("Failed to login with new password: %v", err)
	}

	// Try invalid login
	_, err = Login(ctx, "test@example.com", "wrongpass")
	if err == nil {
		t.Fatalf("Expected error for wrong password")
	}

	// Try verify invalid token
	err = VerifyEmail(ctx, "invalidtoken")
	if err == nil {
		t.Fatalf("Expected error for invalid token")
	}

	// Try change invalid password
	err = ChangePassword(ctx, user.ID, "wrong", "newnew", "")
	if err == nil {
		t.Fatalf("Expected error for changing with wrong old password")
	}
}
