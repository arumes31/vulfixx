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
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token").
			WithArgs("notfound@test.com").
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		genericMsg := "If this email is registered and unverified, a new verification link will be sent."
		_, _, _, err = ResendVerificationToken(ctx, "notfound@test.com")
		if err == nil || err.Error() != genericMsg {
			t.Errorf("expected generic error, got %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("AlreadyVerified", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token").
			WithArgs("verified@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, true, 0, nil, nil))
		mock.ExpectRollback()

		genericMsg := "If this email is registered and unverified, a new verification link will be sent."
		_, _, _, err = ResendVerificationToken(ctx, "verified@test.com")
		if err == nil || err.Error() != genericMsg {
			t.Errorf("expected generic error, got %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
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
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token").
			WithArgs("wait@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, false, 0, &now, "old-token"))
		mock.ExpectRollback()

		genericMsg := "If this email is registered and unverified, a new verification link will be sent."
		_, _, _, err = ResendVerificationToken(ctx, "wait@test.com")
		if err == nil || err.Error() != genericMsg {
			t.Errorf("expected generic error, got %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("Success", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token").
			WithArgs("success@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, false, 0, nil, "old-token"))
		mock.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		token, _, _, err := ResendVerificationToken(ctx, "success@test.com")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if token == "" {
			t.Errorf("expected token, got empty string")
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("UpdateFailure", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token").
			WithArgs("fail@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, false, 0, nil, "old-token"))
		mock.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), 1).
			WillReturnError(pgx.ErrNoRows) // any error to trigger log and fail
		mock.ExpectRollback()

		_, _, _, err = ResendVerificationToken(ctx, "fail@test.com")
		if err == nil {
			t.Error("expected error but got none")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("CommitFailure", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		mock.ExpectBegin()
		mock.ExpectQuery("SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token").
			WithArgs("commitfail@test.com").
			WillReturnRows(mock.NewRows([]string{"id", "is_email_verified", "verification_resend_count", "last_verification_resend_at", "email_verify_token"}).
				AddRow(1, false, 0, nil, "old-token"))
		mock.ExpectExec("UPDATE users").
			WithArgs(pgxmock.AnyArg(), 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit().WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		_, _, _, err = ResendVerificationToken(ctx, "commitfail@test.com")
		if err == nil {
			t.Error("expected error but got none")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestMaskEmail(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "a"},
		{"a@b.com", "a@b.com"},
		{"ab@c.com", "a***@c.com"},
		{"abcde@f.com", "a***@f.com"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			res := maskEmail(tc.input)
			if res != tc.expected {
				t.Errorf("maskEmail(%q) = %q; expected %q", tc.input, res, tc.expected)
			}
		})
	}
}
