package db

import (
	"os"
	"testing"
)

func TestInitDBWithInvalidDSN(t *testing.T) {
	// Set dummy env for invalid DSN test
	_ = os.Setenv("DB_HOST", "invalid_host")
	_ = os.Setenv("DB_PORT", "abc")
	_ = os.Setenv("DB_USER", "user")
	_ = os.Setenv("DB_PASSWORD", "pass")
	_ = os.Setenv("DB_NAME", "db")

	err := InitDB()
	if err == nil {
		t.Fatal("Expected error with invalid DSN (port abc), but got nil")
	}
	CloseDB()
}
