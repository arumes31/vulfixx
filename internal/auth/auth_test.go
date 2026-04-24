package auth

import (
	"context"
	"cve-tracker/internal/db"
	"os"
	"strings"
	"testing"
)

func TestAuthIntegration(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION") == "true" {
		t.Skip("skipping integration test")
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
	_, _ = db.Pool.Exec(ctx, "DELETE FROM users WHERE email IN ('test@example.com', 'admin_init@example.com', 'changed@example.com', 'admin_init2@example.com')")

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

    // Test Email Change Flow
    oldTok, newTok, err := RequestEmailChange(ctx, user.ID, "changed@example.com")
    if err != nil {
        t.Fatalf("Failed to request email change: %v", err)
    }

    // Confirm old
    ok, _, _, err := ConfirmEmailChange(ctx, oldTok)
    if err != nil {
        t.Fatalf("Failed to confirm old email token: %v", err)
    }
    if ok {
        t.Fatalf("Should not be fully confirmed yet")
    }

    // Confirm new
    ok, newEmail, _, err := ConfirmEmailChange(ctx, newTok)
    if err != nil {
        t.Fatalf("Failed to confirm new email token: %v", err)
    }
    if !ok || newEmail != "changed@example.com" {
        t.Fatalf("Expected fully confirmed and correct new email, got ok=%v, email=%s", ok, newEmail)
    }

    // Test InitAdmin
    err = InitAdmin(ctx, "admin_init@example.com", "password", "JBSWY3DPEHPK3PXP")
    if err != nil {
        t.Fatalf("Failed to init admin: %v", err)
    }
    err = InitAdmin(ctx, "", "", "") // should skip
    if err != nil {
        t.Fatalf("Failed to skip empty admin init: %v", err)
    }
    err = InitAdmin(ctx, "admin_init2@example.com", "password", "") // missing totp
    if err == nil {
        t.Fatalf("Expected error missing totp secret")
    }
}
