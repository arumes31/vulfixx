package web

import (
	"encoding/json"
	"log"
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
	resp := APIResponse{
		Success: success,
		Data:    data,
		Error:   errMsg,
		Meta:    meta,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if _, writeErr := w.Write([]byte(`{"success":false,"error":"Internal server error"}`)); writeErr != nil {
			log.Printf("Error writing JSON error response: %v", writeErr)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, writeErr := w.Write(body); writeErr != nil {
		log.Printf("Error writing JSON response: %v", writeErr)
	}
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
