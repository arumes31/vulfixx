package auth

import (
	"context"
	"cve-tracker/internal/db"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestResendVerificationToken(t *testing.T) {
	ctx := context.Background()

	t.Run("UserNotFound", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at").
			WithArgs("notfound@test.com").
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		_, err = ResendVerificationToken(ctx, "notfound@test.com")
		if err == nil || err.Error() != "user not found" {
			t.Errorf("expected user not found, got %v", err)
		}
	})

	t.Run("AlreadyVerified", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at").
			WithArgs("verified@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at"}).
				AddRow(1, true, 0, nil))
		mock.ExpectRollback()

		_, err = ResendVerificationToken(ctx, "verified@test.com")
		if err == nil || err.Error() != "email already verified" {
			t.Errorf("expected email already verified, got %v", err)
		}
	})

	t.Run("WaitTime", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		now := time.Now()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at").
			WithArgs("wait@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at"}).
				AddRow(1, false, 0, &now))
		mock.ExpectRollback()

		_, err = ResendVerificationToken(ctx, "wait@test.com")
		if err == nil {
			t.Errorf("expected please wait error, got nil")
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at").
			WithArgs("success@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at"}).
				AddRow(1, false, 0, nil))
		mock.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		token, err := ResendVerificationToken(ctx, "success@test.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if token == "" {
			t.Errorf("expected token, got empty string")
		}
	})
}
