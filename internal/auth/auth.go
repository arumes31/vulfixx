package auth

import (
	"context"
	"crypto/rand"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"
	"github.com/pquerna/otp/totp"
)
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func Register(ctx context.Context, email, password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, password_hash, email_verify_token, rss_feed_token) VALUES ($1, $2, $3, $4)", email, string(hashedPassword), token, rssToken)
	return token, err
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

func Login(ctx context.Context, email, password string) (*models.User, error) {
	var user models.User
	// Make sure we scan all relevant fields needed
	err := db.Pool.QueryRow(ctx, "SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, ''), is_admin FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.IsTOTPEnabled, &user.TOTPSecret, &user.IsAdmin)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
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

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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
	`, email, string(hashedPassword), totpSecret, rssToken)

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

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(currentPassword))
	if err != nil {
		return errors.New("invalid current password")
	}

	if isTOTPEnabled {
		if !totp.Validate(totpCode, secret) {
			return errors.New("invalid TOTP code")
		}
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Pool.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE id = $2", string(newHash), userID)
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
		return false, "", 0, errors.New("invalid or expired token")
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