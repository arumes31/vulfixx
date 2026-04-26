package worker

import (
	"context"
	"cve-tracker/internal/db"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func processEmailVerification(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := db.RedisClient.BRPop(ctx, 0, "email_verification_queue").Result()
			if err != nil {
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
				}
				continue
			}
			var payload map[string]string
			if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
				log.Printf("Error unmarshaling email verification payload: %v", err)
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
				}
				continue
			}
			sendVerificationEmail(payload["email"], payload["token"])
		}
	}
}

func processEmailChange(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result, err := db.RedisClient.BRPop(ctx, 0, "email_change_queue").Result()
			if err != nil {
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
				}
				continue
			}
			var payload map[string]string
			if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
				log.Printf("Error unmarshaling email change payload: %v", err)
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
				}
				continue
			}
			sendEmailChangeNotification(payload["email"], payload["token"], payload["type"])
		}
	}
}

func sendEmailChangeNotification(email, token, emailType string) {
	subject := "Confirm Your Email Change"
	body := fmt.Sprintf("Please click the link below to confirm your new email address: %s/confirm-email-change?token=%s", os.Getenv("BASE_URL"), token)
	_ = sendEmail(email, subject, body)
}

func sendVerificationEmail(email, token string) {
	subject := "Verify Your Email Address"
	body := fmt.Sprintf("Please click the link below to verify your email address: %s/verify-email?token=%s", os.Getenv("BASE_URL"), token)
	_ = sendEmail(email, subject, body)
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
	cleanSubject := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, subject)
	cleanTo := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, toEmail)

	msg := []byte("To: " + cleanTo + "\r\n" + "Subject: " + cleanSubject + "\r\n" + "Content-Type: text/html; charset=UTF-8\r\n" + "\r\n" + body)
	return sendMailWithTimeout(host, port, user, password, from, []string{cleanTo}, msg)
}
