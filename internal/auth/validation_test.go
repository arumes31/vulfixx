package auth

import (
	"context"
	"testing"
)

func TestPasswordLengthValidation(t *testing.T) {
	ctx := context.Background()

	// Test Register with short password
	_, err := Register(ctx, "short@example.com", "short")
	if err == nil {
		t.Error("Expected error when registering with short password, got nil")
	} else if err.Error() != "password must be at least 8 characters long" {
		t.Errorf("Expected 'password must be at least 8 characters long' error, got '%v'", err)
	}
}
