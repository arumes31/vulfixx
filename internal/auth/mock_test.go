package auth

import (
	"context"
	"errors"
	"testing"

	"cve-tracker/internal/db"

	"github.com/pashagolub/pgxmock/v3"
)

func TestMockedErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("GenerateTokenRandFail", func(t *testing.T) {
		orig := randRead
		randRead = func(b []byte) (int, error) { return 0, errors.New("rand fail") }
		defer func() { randRead = orig }()

		_, err := GenerateToken()
		if err == nil || err.Error() != "rand fail" {
			t.Errorf("expected rand fail, got %v", err)
		}
	})

	t.Run("RegisterArgon2idFail", func(t *testing.T) {
		orig := argon2idGeneratePassword
		argon2idGeneratePassword = func(password string) (string, error) { return "", errors.New("argon2id fail") }
		defer func() { argon2idGeneratePassword = orig }()

		_, err := Register(ctx, "test@test.com", "password")
		if err == nil || err.Error() != "argon2id fail" {
			t.Errorf("expected argon2id fail, got %v", err)
		}
	})

	t.Run("RegisterGenerateTokenFail", func(t *testing.T) {
		orig := randRead
		randRead = func(b []byte) (int, error) { return 0, errors.New("rand fail") }
		defer func() { randRead = orig }()

		_, err := Register(ctx, "test@test.com", "password")
		if err == nil || err.Error() != "rand fail" {
			t.Errorf("expected rand fail, got %v", err)
		}
	})

	t.Run("RegisterGenerateTokenFailSecond", func(t *testing.T) {
		orig := randRead
		count := 0
		randRead = func(b []byte) (int, error) {
			if count == 1 {
				return 0, errors.New("rand fail second")
			}
			count++
			for i := range b {
				b[i] = 0
			}
			return len(b), nil
		}
		defer func() { randRead = orig }()

		_, err := Register(ctx, "test@test.com", "password")
		if err == nil || err.Error() != "rand fail second" {
			t.Errorf("expected rand fail second, got %v", err)
		}
	})

	t.Run("InitAdminArgon2idFail", func(t *testing.T) {
		orig := argon2idGeneratePassword
		argon2idGeneratePassword = func(password string) (string, error) { return "", errors.New("argon2id fail") }
		defer func() { argon2idGeneratePassword = orig }()

		err := InitAdmin(ctx, "admin@test.com", "password", "secret")
		if err == nil || err.Error() != "argon2id fail" {
			t.Errorf("expected argon2id fail, got %v", err)
		}
	})

	t.Run("InitAdminGenerateTokenFail", func(t *testing.T) {
		orig := randRead
		randRead = func(b []byte) (int, error) { return 0, errors.New("rand fail") }
		defer func() { randRead = orig }()

		err := InitAdmin(ctx, "admin@test.com", "password", "secret")
		if err == nil || err.Error() != "rand fail" {
			t.Errorf("expected rand fail, got %v", err)
		}
	})

	t.Run("ChangePasswordArgon2idFail", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("SetupTestDB failed: %v", err)
		}
		defer mock.Close()

		orig := argon2idGeneratePassword
		argon2idGeneratePassword = func(password string) (string, error) { return "", errors.New("argon2id fail") }
		defer func() { argon2idGeneratePassword = orig }()

		// Setup DB mock to pass initial checks
		realHash, _ := hashPasswordArgon2id("password")
		mock.ExpectQuery("SELECT password_hash").WithArgs(1).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(realHash), false, ""))

		err = ChangePassword(ctx, 1, "password", "newpassword", "")
		if err == nil || err.Error() != "argon2id fail" {
			t.Errorf("expected argon2id fail, got %v", err)
		}
	})

	t.Run("RequestEmailChangeGenerateTokenFail", func(t *testing.T) {
		orig := randRead
		randRead = func(b []byte) (int, error) { return 0, errors.New("rand fail") }
		defer func() { randRead = orig }()

		_, _, err := RequestEmailChange(ctx, 1, "new@test.com")
		if err == nil || err.Error() != "rand fail" {
			t.Errorf("expected rand fail, got %v", err)
		}
	})

	t.Run("RequestEmailChangeGenerateTokenFailSecond", func(t *testing.T) {
		orig := randRead
		count := 0
		randRead = func(b []byte) (int, error) {
			if count == 1 {
				return 0, errors.New("rand fail second")
			}
			count++
			for i := range b {
				b[i] = 0
			}
			return len(b), nil
		}
		defer func() { randRead = orig }()

		_, _, err := RequestEmailChange(ctx, 1, "new@test.com")
		if err == nil || err.Error() != "rand fail second" {
			t.Errorf("expected rand fail second, got %v", err)
		}
	})

	t.Run("RequestEmailChangeDBFail", func(t *testing.T) {
		mock, err := db.SetupTestDB()
		if err != nil {
			t.Fatalf("setup test db: %v", err)
		}
		defer mock.Close()

		mock.ExpectExec("INSERT INTO email_change_requests").
			WithArgs(1, "new@test.com", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnError(errors.New("db fail"))

		_, _, err = RequestEmailChange(ctx, 1, "new@test.com")
		if err == nil || err.Error() != "db fail" {
			t.Errorf("expected db fail, got %v", err)
		}
	})
}

func TestVerifyEmailDBFail(t *testing.T) {
	mock, err := db.SetupTestDB()
	if err != nil {
		t.Fatalf("SetupTestDB failed: %v", err)
	}
	defer mock.Close()
	ctx := context.Background()

	mock.ExpectExec("UPDATE users").WithArgs("token").WillReturnError(errors.New("db fail"))
	err = VerifyEmail(ctx, "token")
	if err == nil || err.Error() != "db fail" {
		t.Errorf("expected db fail, got %v", err)
	}
}
