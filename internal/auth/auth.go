package auth

import (
	"context"
	"crypto/rand"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"cve-tracker/internal/security"
	"encoding/hex"
	"errors"
	"fmt"

	"log/slog"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

const MinPasswordLength = 8

var (
	randRead                 = rand.Read
	argon2idGeneratePassword = hashPasswordArgon2id

	ErrConflict = errors.New("unable to create account")
)

func HashPassword(password string) (string, error) {
	return argon2idGeneratePassword(password)
}

// dummyHash is a pre-computed valid argon2id hash of a dummy string.
// This prevents email enumeration via timing attacks when a user is not found,
// while avoiding runtime initialization panics.
var dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$X4fUoUhti1NYpyJWO4K5EQ$eMu2NZT+fjCsjS5+1+DQhG+nJT+wS1ZLXDaZjEvT0d0"

func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := randRead(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func Register(ctx context.Context, email, password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", errors.New("password must be at least 8 characters long")
	}
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return "", err
	}

	token, err := GenerateToken()
	if err != nil {
		return "", err
	}

	rssToken, err := GenerateToken()
	if err != nil {
		return "", err
	}

	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, password_hash, email_verify_token, rss_feed_token) VALUES ($1, $2, $3, $4)", email, hashedPassword, token, rssToken)
	if err != nil {
		// Normalize error to prevent email enumeration
		if !strings.Contains(err.Error(), "unique constraint") && !strings.Contains(err.Error(), "duplicate key") {
			masked := security.MaskEmail(email)
			slog.Error("Registration error", "email", masked, "error", err)
		}
		return "", ErrConflict
	}
	return token, nil
}
func VerifyEmail(ctx context.Context, token string) error {
	res, err := db.Pool.Exec(ctx, "UPDATE users SET is_email_verified = TRUE, email_verify_token = NULL WHERE email_verify_token = $1", token)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return errors.New("invalid or expired token")
	}
	return nil
}

// ResendVerificationToken rotates the verification token and returns
// (newToken, oldToken, oldLastResend, error). The caller should use the old*
// values to call RollbackResend if the downstream email send fails.
func ResendVerificationToken(ctx context.Context, email string) (string, string, *time.Time, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", "", nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID int
	var isVerified bool
	var resendCount int
	var lastResend *time.Time
	var oldToken *string

	genericMsg := "If this email is registered and unverified, a new verification link will be sent."

	err = tx.QueryRow(ctx, "SELECT id, is_email_verified, verification_resend_count, last_verification_resend_at, email_verify_token FROM users WHERE email = $1 FOR UPDATE", email).
		Scan(&userID, &isVerified, &resendCount, &lastResend, &oldToken)
	if err != nil {
		return "", "", nil, errors.New(genericMsg)
	}

	if isVerified {
		return "", "", nil, errors.New(genericMsg)
	}

	if lastResend != nil {
		// Progressive backoff: 10m + (count * 20m)
		waitTime := 10*time.Minute + time.Duration(resendCount)*20*time.Minute
		if time.Since(*lastResend) < waitTime {
			return "", "", nil, errors.New(genericMsg)
		}
	}

	newToken, err := GenerateToken()
	if err != nil {
		slog.Error("Error generating token for resend", "email", security.MaskEmail(email), "error", err)
		return "", "", nil, errors.New(genericMsg)
	}

	_, err = tx.Exec(ctx, `
		UPDATE users 
		SET email_verify_token = $1, 
		    verification_resend_count = verification_resend_count + 1, 
		    last_verification_resend_at = CURRENT_TIMESTAMP 
		WHERE id = $2
	`, newToken, userID)
	if err != nil {
		slog.Error("Error updating verification token", "email", security.MaskEmail(email), "error", err)
		return "", "", nil, errors.New(genericMsg)
	}

	if err = tx.Commit(ctx); err != nil {
		slog.Error("Error committing resend transaction", "email", security.MaskEmail(email), "error", err)
		return "", "", nil, errors.New(genericMsg)
	}

	prevToken := ""
	if oldToken != nil {
		prevToken = *oldToken
	}
	return newToken, prevToken, lastResend, nil
}

// RollbackResend atomically restores the previous email_verify_token, resend count,
// and last_verification_resend_at so the prior verification link remains valid.
func RollbackResend(ctx context.Context, email string, oldToken string, oldLastResend *time.Time) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE users 
		SET email_verify_token = $2,
		    verification_resend_count = GREATEST(0, verification_resend_count - 1),
		    last_verification_resend_at = $3
		WHERE email = $1 AND is_email_verified = FALSE
	`, email, oldToken, oldLastResend)
	return err
}



func Login(ctx context.Context, email, password string) (*models.User, error) {
	var user models.User
	var targetHash string

	// Make sure we scan all relevant fields needed
	err := db.Pool.QueryRow(ctx, "SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, ''), is_admin FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.IsTOTPEnabled, &user.TOTPSecret, &user.IsAdmin)

	if err != nil {
		// User not found, use dummy hash to keep timing consistent
		targetHash = dummyHash
	} else {
		targetHash = user.PasswordHash
	}

	// Always perform the comparison to prevent timing side-channels
	matched, errVer := verifyPasswordArgon2id(targetHash, password)
	var cmpErr error
	if !matched || errVer != nil {
		cmpErr = errors.New("invalid credentials")
	}

	if err != nil || cmpErr != nil {
		return nil, errors.New("invalid credentials")
	}

	return &user, nil
}

// InitAdmin initializes an admin user from environment variables.
// It requires non-empty email, password, and totpSecret.
func InitAdmin(ctx context.Context, email, password, totpSecret string) error {
	if email == "" || password == "" {
		return nil // No admin config provided, skip seeding
	}

	if totpSecret == "" {
		return errors.New("ADMIN_TOTP_SECRET is required for admin initialization")
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	rssToken, err := GenerateToken()
	if err != nil {
		return err
	}

	_, err = db.Pool.Exec(ctx, `
		INSERT INTO users (email, password_hash, is_email_verified, is_admin, totp_secret, is_totp_enabled, rss_feed_token)
		VALUES ($1, $2, TRUE, TRUE, $3, TRUE, $4)
		ON CONFLICT (email) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			is_admin = TRUE,
			totp_secret = EXCLUDED.totp_secret,
			is_totp_enabled = TRUE
	`, email, hashedPassword, totpSecret, rssToken)

	return err
}

func ChangePassword(ctx context.Context, userID int, currentPassword, newPassword, totpCode string) error {
	var hash string
	var isTOTPEnabled bool
	var secret string
	err := db.Pool.QueryRow(ctx, "SELECT password_hash, is_totp_enabled, COALESCE(totp_secret, '') FROM users WHERE id = $1", userID).Scan(&hash, &isTOTPEnabled, &secret)
	if err != nil {
		return errors.New("user not found")
	}

	matched, errVer := verifyPasswordArgon2id(hash, currentPassword)
	if !matched || errVer != nil {
		return errors.New("invalid current password")
	}

	if isTOTPEnabled {
		if !totp.Validate(totpCode, secret) {
			return errors.New("invalid TOTP code")
		}
	}

	if len(newPassword) < MinPasswordLength {
		return errors.New("password must be at least 8 characters long")
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = db.Pool.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE id = $2", newHash, userID)
	return err
}

func RequestEmailChange(ctx context.Context, userID int, newEmail string) (string, string, error) {
	oldToken, err := GenerateToken()
	if err != nil {
		return "", "", err
	}
	newToken, err := GenerateToken()
	if err != nil {
		return "", "", err
	}

	_, err = db.Pool.Exec(ctx, `
		INSERT INTO email_change_requests (user_id, new_email, old_email_token, new_email_token)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET
			new_email = EXCLUDED.new_email,
			old_email_token = EXCLUDED.old_email_token,
			new_email_token = EXCLUDED.new_email_token,
			old_email_confirmed = FALSE,
			new_email_confirmed = FALSE,
			created_at = CURRENT_TIMESTAMP
	`, userID, newEmail, oldToken, newToken)

	return oldToken, newToken, err
}

// ConfirmEmailChange confirms a token from an email change flow.
// Returns (fullyConfirmed, newEmail, userID, error).
// The entire lookup, flag update, and final email change are done within a
// single transaction with a row lock (FOR UPDATE) to prevent races.
func ConfirmEmailChange(ctx context.Context, token string) (bool, string, int, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return false, "", 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the row and fetch all fields in one query, with TTL check
	var userID int
	var newEmail string
	var oldConfirmed, newConfirmed bool
	var oldEmailToken, newEmailToken string

	err = tx.QueryRow(ctx, `
		SELECT user_id, new_email, old_email_confirmed, new_email_confirmed,
		       old_email_token, new_email_token
		FROM email_change_requests
		WHERE (old_email_token = $1 OR new_email_token = $1)
		  AND created_at > NOW() - INTERVAL '24 hours'
		FOR UPDATE
	`, token).Scan(&userID, &newEmail, &oldConfirmed, &newConfirmed, &oldEmailToken, &newEmailToken)

	if err != nil {
		fmt.Println("SCAN ERROR:", err)
		return false, "", 0, fmt.Errorf("invalid or expired token: %w", err)
	}

	// Determine which token was used
	isOldToken := (oldEmailToken == token)

	if isOldToken {
		oldConfirmed = true
		_, err = tx.Exec(ctx, "UPDATE email_change_requests SET old_email_confirmed = TRUE WHERE user_id = $1", userID)
	} else {
		newConfirmed = true
		_, err = tx.Exec(ctx, "UPDATE email_change_requests SET new_email_confirmed = TRUE WHERE user_id = $1", userID)
	}

	if err != nil {
		return false, "", 0, err
	}

	if oldConfirmed && newConfirmed {
		// Both confirmed! Update user email and clean up request atomically
		_, err = tx.Exec(ctx, "UPDATE users SET email = $1, is_email_verified = TRUE WHERE id = $2", newEmail, userID)
		if err != nil {
			return false, "", 0, err
		}
		_, err = tx.Exec(ctx, "DELETE FROM email_change_requests WHERE user_id = $1", userID)

		if err != nil {
			return false, "", 0, err
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return false, "", 0, err
	}

	if oldConfirmed && newConfirmed {
		return true, newEmail, userID, nil
	}

	return false, "", userID, nil
}
