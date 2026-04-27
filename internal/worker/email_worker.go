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
		email := payload["email"]
		token := payload["token"]
		if email == "" || token == "" {
			log.Printf("Worker: Invalid email verification payload: email=%q, token=%q", email, token)
			continue
		}
		if err := sendVerificationEmail(email, token); err != nil {
			log.Printf("Worker: Failed to send verification email to %s: %v. Re-enqueueing...", email, err)
			// Re-enqueue with a small delay or just push back to the queue
			payload["retries"] = fmt.Sprintf("%v", payload["retries"]) // simplistic retry counter if needed
			newPayload, _ := json.Marshal(payload)
			_ = db.RedisClient.LPush(ctx, "email_verification_queue", newPayload).Err()
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
		email := payload["email"]
		token := payload["token"]
		emailType := payload["type"]
		if email == "" || token == "" {
			log.Printf("Worker: Invalid email change payload: email=%q, token=%q", email, token)
			continue
		}
		if err := sendEmailChangeNotification(email, token, emailType); err != nil {
			log.Printf("Worker: Failed to send email change notification to %s: %v", email, err)
		}
	}
}

func sendEmailChangeNotification(email, token, emailType string) error {
	subject := "Confirm Your Email Change"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" { baseURL = "http://localhost:8080" }
	body := fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Please click the link below to confirm your new email address:</p><p><a href=\"%s/confirm-email-change?token=%s\">%s/confirm-email-change?token=%s</a></p></div>", baseURL, token, baseURL, token)
	return GlobalEmailSender.SendEmail(email, subject, body)
}

func sendVerificationEmail(email, token string) error {
	subject := "Verify Your Email Address"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" { baseURL = "http://localhost:8080" }
	body := fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Welcome to Vulfixx! Please click the link below to verify your email address:</p><p><a href=\"%s/verify-email?token=%s\">%s/verify-email?token=%s</a></p></div>", baseURL, token, baseURL, token)
	return GlobalEmailSender.SendEmail(email, subject, body)
}

func sendEmail(toEmail, subject, body string) error {
	return GlobalEmailSender.SendEmail(toEmail, subject, body)
}
