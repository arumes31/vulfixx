package auth

import (
	"context"
	"cve-tracker/internal/db"
	"cve-tracker/internal/models"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func Register(ctx context.Context, email, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Pool.Exec(ctx, "INSERT INTO users (email, password_hash) VALUES ($1, $2)", email, string(hashedPassword))
	return err
}

func Login(ctx context.Context, email, password string) (*models.User, error) {
	var user models.User
	err := db.Pool.QueryRow(ctx, "SELECT id, email, password_hash FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	return &user, nil
}
