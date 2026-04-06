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

	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, password_hash, email_verify_token) VALUES ($1, $2, $3)", email, string(hashedPassword), token)
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
	err := db.Pool.QueryRow(ctx, "SELECT id, email, password_hash, is_email_verified, is_totp_enabled, COALESCE(totp_secret, '') FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.IsTOTPEnabled, &user.TOTPSecret)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	return &user, nil
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

func ConfirmEmailChange(ctx context.Context, token string) (bool, string, error) {
	// Check if it's an old email token
	var userID int
	var newEmail string
	var oldConfirmed, newConfirmed bool

	err := db.Pool.QueryRow(ctx, `
		SELECT user_id, new_email, old_email_confirmed, new_email_confirmed
		FROM email_change_requests
		WHERE old_email_token = $1 OR new_email_token = $1
	`, token).Scan(&userID, &newEmail, &oldConfirmed, &newConfirmed)

	if err != nil {
		return false, "", errors.New("invalid or expired token")
	}

	// Determine which token was used
	var isOldToken bool
	err = db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM email_change_requests WHERE old_email_token = $1)", token).Scan(&isOldToken)
	if err != nil {
		return false, "", err
	}

	if isOldToken {
		oldConfirmed = true
		_, err = db.Pool.Exec(ctx, "UPDATE email_change_requests SET old_email_confirmed = TRUE WHERE user_id = $1", userID)
	} else {
		newConfirmed = true
		_, err = db.Pool.Exec(ctx, "UPDATE email_change_requests SET new_email_confirmed = TRUE WHERE user_id = $1", userID)
	}

	if err != nil {
		return false, "", err
	}

	if oldConfirmed && newConfirmed {
		// Both confirmed! Update user email
		_, err = db.Pool.Exec(ctx, "UPDATE users SET email = $1, is_email_verified = TRUE WHERE id = $2", newEmail, userID)
		if err != nil {
			return false, "", err
		}
		// Delete request
		_, _ = db.Pool.Exec(ctx, "DELETE FROM email_change_requests WHERE user_id = $1", userID)
		return true, newEmail, nil
	}

	return false, "", nil
}