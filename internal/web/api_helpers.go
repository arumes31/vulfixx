package web

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
)

// APIResponse represents the standardized JSON response envelope.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
}

// SendJSONResponse serializes and sends a standardized JSON API response envelope.
func SendJSONResponse(w http.ResponseWriter, statusCode int, success bool, data interface{}, errMsg string, meta interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := APIResponse{
		Success: success,
		Data:    data,
		Error:   errMsg,
		Meta:    meta,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// Validate is the global validator instance.
var Validate = validator.New()

// LoginRequest holds structured validator annotations for the login form.
type LoginRequest struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
	TOTPCode string `validate:"omitempty,numeric,len=6"`
}

// RegisterRequest holds structured validator annotations for the registration form.
type RegisterRequest struct {
	Email           string `validate:"required,email"`
	Password        string `validate:"required,min=8"`
	PasswordConfirm string `validate:"required,eqfield=Password"`
	Captcha         string `validate:"required"`
}

// ChangePasswordRequest holds structured validator annotations for updating passwords.
type ChangePasswordRequest struct {
	CurrentPassword string `validate:"required"`
	NewPassword     string `validate:"required,min=8"`
	ConfirmPassword string `validate:"required,eqfield=NewPassword"`
	TOTPCode        string `validate:"omitempty,numeric,len=6"`
}

// ChangeEmailRequest holds structured validator annotations for updating emails.
type ChangeEmailRequest struct {
	NewEmail string `validate:"required,email"`
	Password string `validate:"required"`
}
