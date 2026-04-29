package auth

import (
	"context"
	"cve-tracker/internal/db"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthMock(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	ctx := context.Background()

	// Test Register
	mock.ExpectExec("INSERT INTO users").
		WithArgs("test@example.com", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	token, err := Register(ctx, "test@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to register: %v", err)
	}

	// Test VerifyEmail
	mock.ExpectExec("UPDATE users SET is_email_verified = TRUE").
		WithArgs(token).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("Failed to verify email: %v", err)
	}

	// Test Login
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	rows := pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
		AddRow(1, "test@example.com", string(hashedPassword), true, false, "", false)
	mock.ExpectQuery("SELECT id, email, password_hash").
		WithArgs("test@example.com").
		WillReturnRows(rows)

	user, err := Login(ctx, "test@example.com", "password")
	if err != nil || user.Email != "test@example.com" {
		t.Fatalf("Failed to login or wrong email: %v", err)
	}

	// Test ChangePassword
	mock.ExpectQuery("SELECT password_hash, is_totp_enabled").
		WithArgs(1).
		WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hashedPassword), false, ""))
	mock.ExpectExec("UPDATE users SET password_hash").
		WithArgs(pgxmock.AnyArg(), 1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err = ChangePassword(ctx, 1, "password", "newpassword", "")
	if err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}

	// Test InitAdmin
	mock.ExpectExec("INSERT INTO users").
		WithArgs("admin@example.com", pgxmock.AnyArg(), "secret", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	err = InitAdmin(ctx, "admin@example.com", "adminpass", "secret")
	if err != nil {
		t.Fatalf("Failed to init admin: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations in TestAuthMock: %v", err)
	}
}

func TestEmailChangeFlow(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("failed to setup mock db: %v", err)
	}
	defer mock.Close()

	ctx := context.Background()

	// RequestEmailChange
	mock.ExpectExec("INSERT INTO email_change_requests").
		WithArgs(1, "new@example.com", pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	oldToken, newToken, err := RequestEmailChange(ctx, 1, "new@example.com")
	if err != nil {
		t.Fatalf("Failed to request email change: %v", err)
	}

	// ConfirmEmailChange (Old Token)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT user_id, new_email, old_email_confirmed, new_email_confirmed").
		WithArgs(oldToken).
		WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
			AddRow(1, "new@example.com", false, false, oldToken, newToken))
	mock.ExpectExec("UPDATE email_change_requests SET old_email_confirmed = TRUE").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()

	confirmed, email, uid, err := ConfirmEmailChange(ctx, oldToken)
	_ = email
	if err != nil || confirmed || uid != 1 {
		t.Fatalf("Failed first confirmation: %v, %v, %d", err, confirmed, uid)
	}

	// ConfirmEmailChange (New Token)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT user_id, new_email, old_email_confirmed, new_email_confirmed").
		WithArgs(newToken).
		WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
			AddRow(1, "new@example.com", true, false, oldToken, newToken))
	mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("UPDATE users SET email = \\$1").
		WithArgs("new@example.com", 1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec("DELETE FROM email_change_requests").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	mock.ExpectCommit()

	confirmed, email, uid, err = ConfirmEmailChange(ctx, newToken)
	_ = uid
	if err != nil || !confirmed || email != "new@example.com" {
		t.Fatalf("Failed final confirmation: %v, %v, %s", err, confirmed, email)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations in TestEmailChangeFlow: %v", err)
	}
}

func TestAuthErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("RegisterDBFail", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectExec("INSERT INTO users").WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnError(errors.New("db fail"))
		_, err := Register(ctx, "fail@example.com", "password123")
		if err == nil || !errors.Is(err, ErrConflict) {
			t.Errorf("expected ErrConflict on register db fail, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("VerifyEmailInvalidToken", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectExec("UPDATE users").WithArgs("bad").WillReturnResult(pgxmock.NewResult("UPDATE", 0))
		err := VerifyEmail(ctx, "bad")
		if err == nil || err.Error() != "invalid or expired token" {
			t.Errorf("expected invalid token error, got %v", err)
		}
	})

	t.Run("LoginUserNotFound", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectQuery("SELECT id, email").WithArgs("none@example.com").WillReturnError(errors.New("not found"))
		_, err := Login(ctx, "none@example.com", "pass")
		if err == nil || err.Error() != "invalid credentials" {
			t.Errorf("expected invalid credentials error, got %v", err)
		}
	})

	t.Run("LoginWrongPassword", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT id, email").WithArgs("test@example.com").
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "password_hash", "is_email_verified", "is_totp_enabled", "totp_secret", "is_admin"}).
				AddRow(1, "test@example.com", string(hashedPassword), true, false, "", false))
		_, err := Login(ctx, "test@example.com", "wrong")
		if err == nil || err.Error() != "invalid credentials" {
			t.Errorf("expected invalid credentials for wrong pass, got %v", err)
		}
	})

	t.Run("InitAdminMissingTOTP", func(t *testing.T) {
		err := InitAdmin(ctx, "admin@test.com", "pass", "")
		if err == nil || err.Error() != "ADMIN_TOTP_SECRET is required for admin initialization" {
			t.Errorf("expected missing totp secret error, got %v", err)
		}
	})

	t.Run("ChangePasswordUserNotFound", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectQuery("SELECT password_hash").WithArgs(99).WillReturnError(errors.New("not found"))
		err := ChangePassword(ctx, 99, "old", "new", "")
		if err == nil || err.Error() != "user not found" {
			t.Errorf("expected user not found error, got %v", err)
		}
	})

	t.Run("ChangePasswordWrongCurrent", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hashedPassword), false, ""))
		err := ChangePassword(ctx, 1, "wrong", "new", "")
		if err == nil || err.Error() != "invalid current password" {
			t.Errorf("expected invalid current pass error, got %v", err)
		}
	})

	t.Run("ChangePasswordInvalidTOTP", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hashedPassword), true, "JBSWY3DPEHPK3PXP"))
		err := ChangePassword(ctx, 1, "password", "new", "000000")
		if err == nil || err.Error() != "invalid TOTP code" {
			t.Errorf("expected invalid TOTP error, got %v", err)
		}
	})

	t.Run("ChangePasswordShortNewPassword", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(hashedPassword), false, ""))
		err := ChangePassword(ctx, 1, "password", "short", "")
		if err == nil || err.Error() != "password must be at least 8 characters long" {
			t.Errorf("expected short password error, got %v", err)
		}
	})

	t.Run("InitAdminEmpty", func(t *testing.T) {
		err := InitAdmin(ctx, "", "", "")
		if err != nil {
			t.Errorf("expected no error for empty admin config, got %v", err)
		}
	})
}

func TestConfirmEmailChangeMore(t *testing.T) {
	ctx := context.Background()

	t.Run("TxBeginFail", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin().WillReturnError(errors.New("begin fail"))
		_, _, _, err := ConfirmEmailChange(ctx, "token")
		if err == nil {
			t.Error("expected error on begin fail")
		}
	})

	t.Run("DeterminationOfToken", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin()
		// Test using new_email_token instead of old
		mock.ExpectQuery("SELECT user_id").WithArgs("newtok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", false, false, "oldtok", "newtok"))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").
			WithArgs(1).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		confirmed, _, _, err := ConfirmEmailChange(ctx, "newtok")
		if err != nil || confirmed {
			t.Errorf("expected no error and not fully confirmed, got %v, %v", err, confirmed)
		}
	})

	t.Run("ExecFail", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id").WithArgs("tok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", false, false, "tok", "other"))
		mock.ExpectExec("UPDATE email_change_requests").WithArgs(1).WillReturnError(errors.New("exec fail"))
		mock.ExpectRollback()
		_, _, _, err := ConfirmEmailChange(ctx, "tok")
		if err == nil || err.Error() != "exec fail" {
			t.Errorf("expected exec fail, got %v", err)
		}
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id").WithArgs("bad").WillReturnError(errors.New("no row"))
		mock.ExpectRollback()
		_, _, _, err := ConfirmEmailChange(ctx, "bad")
		if err == nil {
			t.Error("expected error on token not found")
		}
	})

	t.Run("CommitFail", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id").WithArgs("tok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", false, false, "tok", "other"))
		mock.ExpectExec("UPDATE email_change_requests").WithArgs(1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit().WillReturnError(errors.New("commit fail"))
		mock.ExpectRollback()
		_, _, _, err := ConfirmEmailChange(ctx, "tok")
		if err == nil || err.Error() != "commit fail" {
			t.Errorf("expected commit fail, got %v", err)
		}
	})

	t.Run("FinalUpdateFail", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id").WithArgs("tok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", true, false, "other", "tok"))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").WithArgs(1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email = \\$1").WithArgs("new@test.com", 1).WillReturnError(errors.New("update user fail"))
		mock.ExpectRollback()
		_, _, _, err := ConfirmEmailChange(ctx, "tok")
		if err == nil || err.Error() != "update user fail" {
			t.Errorf("expected update user fail, got %v", err)
		}
	})

	t.Run("FinalDeleteFail", func(t *testing.T) {
		mock, _ := db.SetupTestDB()
		defer mock.Close()
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT user_id").WithArgs("tok").
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "new_email", "old_email_confirmed", "new_email_confirmed", "old_email_token", "new_email_token"}).
				AddRow(1, "new@test.com", true, false, "other", "tok"))
		mock.ExpectExec("UPDATE email_change_requests SET new_email_confirmed = TRUE").WithArgs(1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("UPDATE users SET email = \\$1").WithArgs("new@test.com", 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec("DELETE FROM email_change_requests").WithArgs(1).WillReturnError(errors.New("delete request fail"))
		mock.ExpectRollback()
		_, _, _, err := ConfirmEmailChange(ctx, "tok")
		if err == nil || err.Error() != "delete request fail" {
			t.Errorf("expected delete request fail, got %v", err)
		}
	})
}

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
		realHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
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
