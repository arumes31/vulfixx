package auth

import (
	"context"
	"cve-tracker/internal/db"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"
)

func TestEmailChangeFlow_Coverage(t *testing.T) {
	ctx := context.Background()
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	t.Run("RequestEmailChange", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO email_change_requests").
			WithArgs(1, "new@example.com", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		oldTok, newTok, err := RequestEmailChange(ctx, 1, "new@example.com")
		if err != nil {
			t.Errorf("RequestEmailChange failed: %v", err)
		}
		if oldTok == "" || newTok == "" {
			t.Error("expected tokens to be generated")
		}
	})

	t.Run("ConfirmEmailChange_InvalidToken", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email").
			WithArgs("invalid").
			WillReturnError(pgx.ErrNoRows)
		mock.ExpectRollback()

		confirmed, email, uid, err := ConfirmEmailChange(ctx, "invalid")
		if confirmed || email != "" || uid != 0 || err == nil {
			t.Errorf("expected failure, got confirmed=%v, email=%q, uid=%d, err=%v", confirmed, email, uid, err)
		}
	})

	t.Run("ConfirmEmailChange_FullCycle", func(t *testing.T) {
		oldTok := "old-tok"
		newTok := "new-tok"
		newEmail := "new@example.com"
		userID := 1

		// 1. Confirm old token
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email").
			WithArgs(oldTok).
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(userID, newEmail, false, false, oldTok, newTok))
		mock.ExpectExec("UPDATE email_change_requests SET old_email_confirmed = TRUE").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		confirmed, email, uid, err := ConfirmEmailChange(ctx, oldTok)
		if err != nil || confirmed || email != "" || uid != userID {
			t.Errorf("expected half-confirmation, got err=%v, confirmed=%v, email=%q, uid=%d", err, confirmed, email, uid)
		}

		// 2. Confirm new token
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id, new_email").
			WithArgs(newTok).
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(userID, newEmail, true, false, oldTok, newTok))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email = \\$1, is_email_verified = TRUE").
			WithArgs(newEmail, userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM email_change_requests").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectCommit()

		confirmed, email, uid, err = ConfirmEmailChange(ctx, newTok)
		if err != nil || !confirmed || email != newEmail || uid != userID {
			t.Errorf("expected full-confirmation, got err=%v, confirmed=%v, email=%q, uid=%d", err, confirmed, email, uid)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestRollbackResend(t *testing.T) {
	ctx := context.Background()
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("UPDATE users SET verification_resend_count = GREATEST").
		WithArgs("test@example.com").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = RollbackResend(ctx, "test@example.com")
	if err != nil {
		t.Errorf("RollbackResend failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
