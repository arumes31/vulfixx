package worker

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

func processEmailVerification(ctx context.Context) {
	for {
		result, err := db.RedisClient.BRPop(ctx, 0, "email_verification_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Worker: Error reading from email verification queue: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		var payload map[string]string
		if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
			log.Printf("Worker: Error unmarshaling email verification payload: %v", err)
			continue
		}
		if err := sendVerificationEmail(payload["email"], payload["token"]); err != nil {
			log.Printf("Worker: Failed to send verification email to %s: %v", payload["email"], err)
		}
	}
}

func processEmailChange(ctx context.Context) {
	for {
		result, err := db.RedisClient.BRPop(ctx, 1*time.Second, "email_change_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		var payload map[string]string
		if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
			log.Printf("Worker: Error unmarshaling email change payload: %v", err)
			continue
		}
		if err := sendEmailChangeNotification(payload["email"], payload["token"], payload["type"]); err != nil {
			log.Printf("Worker: Failed to send email change notification to %s: %v", payload["email"], err)
		}
	}
}

func sendEmailChangeNotification(email, token, emailType string) error {
	subject := "Confirm Your Email Change"
	body := fmt.Sprintf("Please click the link below to confirm your new email address: %s/confirm-email-change?token=%s", os.Getenv("BASE_URL"), token)
	return sendEmail(email, subject, body)
}

func sendVerificationEmail(email, token string) error {
	subject := "Verify Your Email Address"
	body := fmt.Sprintf("Please click the link below to verify your email address: %s/verify-email?token=%s", os.Getenv("BASE_URL"), token)
	return sendEmail(email, subject, body)
}

func sendEmail(toEmail, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if host == "" || from == "" {
		return fmt.Errorf("SMTP configuration missing")
	}

	// Validate subject and email to prevent header injection
	cleanSubject := sanitizeHeader(subject)
	cleanTo, err := sanitizeEmail(toEmail)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}

	msg := []byte("To: " + cleanTo + "\r\n" + "Subject: " + cleanSubject + "\r\n" + "Content-Type: text/html; charset=UTF-8\r\n" + "\r\n" + body)
	return sendMailWithTimeout(host, port, user, password, from, []string{cleanTo}, msg)
}
