package auth

import (
	"context"
	"cve-tracker/internal/db"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

// By default an existing admin keeps its password and enrolled TOTP secret, so
// credentials rotated in the UI are not reverted on restart.
func TestInitAdmin_SeedDoesNotOverwriteCredentials(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup test db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec(`(?s)ON CONFLICT \(email\) DO UPDATE SET\s+is_admin = TRUE,\s+totp_secret = CASE`).
		WithArgs("admin@test.com", pgxmock.AnyArg(), "secret", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 0))

	if err := InitAdmin(context.Background(), "admin@test.com", "password", "secret"); err != nil {
		t.Fatalf("InitAdmin: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestInitAdminWithReset_OverwritesCredentials(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("setup test db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec(`(?s)ON CONFLICT \(email\) DO UPDATE SET\s+password_hash = EXCLUDED.password_hash`).
		WithArgs("admin@test.com", pgxmock.AnyArg(), "secret", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	if err := InitAdminWithReset(context.Background(), "admin@test.com", "password", "secret", true); err != nil {
		t.Fatalf("InitAdminWithReset: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
