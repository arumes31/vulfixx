package auth

import (
	"context"
	"cve-tracker/internal/db"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestExtraCoverage(t *testing.T) {
	ctx := context.Background()

	t.Run("ConfirmEmailChange_ElseBranchExecFail", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()
		mock.ExpectBegin()
		// token="newtok", old_email_token="oldtok" => isOldToken=false
		mock.ExpectQuery("SELECT user_id").WithArgs("newtok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", false, false, "oldtok", "newtok"))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").
			WithArgs(1).
			WillReturnError(errors.New("else exec fail"))
		mock.ExpectRollback()
		_, _, _, err = ConfirmEmailChange(ctx, "newtok")
		if err == nil || err.Error() != "else exec fail" {
			t.Errorf("expected else exec fail, got %v", err)
		}
	})

	t.Run("ConfirmEmailChange_FinalUpdateFail_isOldToken", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()
		mock.ExpectBegin()
		// token="oldtok", old_email_token="oldtok" => isOldToken=true
		// new_email_confirmed=true in DB so it enters final block
		mock.ExpectQuery("SELECT user_id").WithArgs("oldtok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", false, true, "oldtok", "newtok"))
		mock.ExpectExec("UPDATE email_change_requests SET old_email_confirmed = TRUE").
			WithArgs(1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email = \\$1").
			WithArgs("new@test.com", 1).
			WillReturnError(errors.New("update user fail"))
		mock.ExpectRollback()
		_, _, _, err = ConfirmEmailChange(ctx, "oldtok")
		if err == nil || err.Error() != "update user fail" {
			t.Errorf("expected update user fail, got %v", err)
		}
	})

	t.Run("ConfirmEmailChange_FinalDeleteFail_isOldToken", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()
		mock.ExpectBegin()
		// token="oldtok", old_email_token="oldtok" => isOldToken=true
		// new_email_confirmed=true in DB so it enters final block
		mock.ExpectQuery("SELECT user_id").WithArgs("oldtok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", false, true, "oldtok", "newtok"))
		mock.ExpectExec("UPDATE email_change_requests SET old_email_confirmed = TRUE").
			WithArgs(1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email = \\$1").
			WithArgs("new@test.com", 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM email_change_requests").
			WithArgs(1).
			WillReturnError(errors.New("delete request fail"))
		mock.ExpectRollback()
		_, _, _, err = ConfirmEmailChange(ctx, "oldtok")
		if err == nil || err.Error() != "delete request fail" {
			t.Errorf("expected delete request fail, got %v", err)
		}
	})

	t.Run("ConfirmEmailChange_CommitFail_isOldToken", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id").WithArgs("oldtok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", true, true, "oldtok", "newtok"))
		// isOldToken=true. It will call UPDATE email_change_requests.
		mock.ExpectExec("UPDATE email_change_requests SET old_email_confirmed = TRUE").
			WithArgs(1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		// oldConfirmed && newConfirmed is true.
		mock.ExpectExec("UPDATE users SET email = \\$1").
			WithArgs("new@test.com", 1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM email_change_requests").
			WithArgs(1).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))
		mock.ExpectCommit().WillReturnError(errors.New("commit fail"))
		mock.ExpectRollback()
		_, _, _, err = ConfirmEmailChange(ctx, "oldtok")
		if err == nil || err.Error() != "commit fail" {
			t.Errorf("expected commit fail, got %v", err)
		}
	})

	t.Run("ChangePassword_FinalExecFail", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()
		// Mock initial query
		realHash, _ := bcryptGeneratePassword([]byte("password"), 10)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(realHash), false, ""))
		// Mock final exec fail
		mock.ExpectExec("UPDATE users SET password_hash").
			WithArgs(pgxmock.AnyArg(), 1).
			WillReturnError(errors.New("update pass fail"))
		err = ChangePassword(ctx, 1, "password", "newpassword", "")
		if err == nil || err.Error() != "update pass fail" {
			t.Errorf("expected update pass fail, got %v", err)
		}
	})

	t.Run("InitAdmin_DBFail", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()
		mock.ExpectExec("INSERT INTO users").
			WithArgs("admin@test.com", pgxmock.AnyArg(), "secret", pgxmock.AnyArg()).
			WillReturnError(errors.New("init admin db fail"))
		err = InitAdmin(ctx, "admin@test.com", "password", "secret")
		if err == nil || err.Error() != "init admin db fail" {
			t.Errorf("expected init admin db fail, got %v", err)
		}
	})
}
