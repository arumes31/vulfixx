package auth

import (
        "context"
        "cve-tracker/internal/db"
        "errors"
        "testing"

        "github.com/pashagolub/pgxmock/v3"
        "golang.org/x/crypto/bcrypt"
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

        t.Run("RegisterBcryptFail", func(t *testing.T) {
                orig := bcryptGeneratePassword
                bcryptGeneratePassword = func(password []byte, cost int) ([]byte, error) { return nil, errors.New("bcrypt fail") }
                defer func() { bcryptGeneratePassword = orig }()

                _, err := Register(ctx, "test@test.com", "password")
                if err == nil || err.Error() != "bcrypt fail" {
                        t.Errorf("expected bcrypt fail, got %v", err)
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
                        for i := range b { b[i] = 0 }
                        return len(b), nil
                }
                defer func() { randRead = orig }()

                _, err := Register(ctx, "test@test.com", "password")
                if err == nil || err.Error() != "rand fail second" {
                        t.Errorf("expected rand fail second, got %v", err)
                }
        })

        t.Run("InitAdminBcryptFail", func(t *testing.T) {
                orig := bcryptGeneratePassword
                bcryptGeneratePassword = func(password []byte, cost int) ([]byte, error) { return nil, errors.New("bcrypt fail") }
                defer func() { bcryptGeneratePassword = orig }()

                err := InitAdmin(ctx, "admin@test.com", "password", "secret")
                if err == nil || err.Error() != "bcrypt fail" {
                        t.Errorf("expected bcrypt fail, got %v", err)
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

        t.Run("ChangePasswordBcryptFail", func(t *testing.T) {
                mock, _ := db.SetupTestDB()
                defer mock.Close()
                
                orig := bcryptGeneratePassword
                bcryptGeneratePassword = func(password []byte, cost int) ([]byte, error) { return nil, errors.New("bcrypt fail") }
                defer func() { bcryptGeneratePassword = orig }()

                // Setup DB mock to pass initial checks
                // Hash for "password" is $2a$10$8K1p/a0dxv.pS9Zf/nE7u.8K1p/a0dxv.pS9Zf/nE7u.8K1p/a0dxv.pS9Zf/nE7u. (fake but let's use a real one)
                realHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
                mock.ExpectQuery("SELECT password_hash").WithArgs(1).
                        WillReturnRows(pgxmock.NewRows([]string{"password_hash", "is_totp_enabled", "totp_secret"}).AddRow(string(realHash), false, ""))

                err := ChangePassword(ctx, 1, "password", "newpassword", "")
                if err == nil || err.Error() != "bcrypt fail" {
                        t.Errorf("expected bcrypt fail, got %v", err)
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
                        for i := range b { b[i] = 0 }
                        return len(b), nil
                }
                defer func() { randRead = orig }()

                _, _, err := RequestEmailChange(ctx, 1, "new@test.com")
                if err == nil || err.Error() != "rand fail second" {
                        t.Errorf("expected rand fail second, got %v", err)
                }
        })

        t.Run("RequestEmailChangeDBFail", func(t *testing.T) {
                mock, _ := db.SetupTestDB()
                defer mock.Close()

                mock.ExpectExec("INSERT INTO email_change_requests").
                        WithArgs(1, "new@test.com", pgxmock.AnyArg(), pgxmock.AnyArg()).
                        WillReturnError(errors.New("db fail"))

                _, _, err := RequestEmailChange(ctx, 1, "new@test.com")
                if err == nil || err.Error() != "db fail" {
                        t.Errorf("expected db fail, got %v", err)
                }
        })
}

func TestVerifyEmailDBFail(t *testing.T) {
        mock, _ := db.SetupTestDB()
        defer mock.Close()
        ctx := context.Background()

        mock.ExpectExec("UPDATE users").WithArgs("token").WillReturnError(errors.New("db fail"))
        err := VerifyEmail(ctx, "token")
        if err == nil || err.Error() != "db fail" {
                t.Errorf("expected db fail, got %v", err)
        }
}
