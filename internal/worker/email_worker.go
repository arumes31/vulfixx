package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

const maxEmailRetries = 5

func (w *Worker) processEmailVerification(ctx context.Context) {
	for {
		result, err := w.Redis.BRPop(ctx, 0, "email_verification_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Worker: Error reading from email verification queue: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
			log.Printf("Worker: Error unmarshaling email verification payload: %v", err)
			continue
		}
		email, _ := payload["email"].(string)
		token, _ := payload["token"].(string)
		if email == "" || token == "" {
			log.Printf("Worker: Invalid email verification payload: email=%q, token=%q", email, token)
			continue
		}

		// Track retries
		retries := 0
		if r, ok := payload["retries"].(float64); ok {
			retries = int(r)
		}

		if err := w.sendVerificationEmail(email, token); err != nil {
			log.Printf("Worker: Failed to send verification email to %s (attempt %d): %v", email, retries+1, err)
			if retries >= maxEmailRetries {
				log.Printf("Worker: Permanently failed to send verification email to %s after %d attempts", email, maxEmailRetries)
				continue
			}
			payload["retries"] = retries + 1
			newPayload, _ := json.Marshal(payload)
			// Exponential backoff: push to delayed queue using ZADD with score=now+delay
			delay := time.Duration(math.Pow(2, float64(retries))) * time.Second
			score := float64(time.Now().Add(delay).UnixMilli())
			_ = w.Redis.ZAdd(ctx, "email_verification_delayed", redis.Z{Score: score, Member: string(newPayload)}).Err()
		}
	}
}

func (w *Worker) processEmailChange(ctx context.Context) {
	for {
		result, err := w.Redis.BRPop(ctx, 1*time.Second, "email_change_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(result[1]), &payload); err != nil {
			log.Printf("Worker: Error unmarshaling email change payload: %v", err)
			continue
		}
		email, _ := payload["email"].(string)
		token, _ := payload["token"].(string)
		emailType, _ := payload["type"].(string)
		if email == "" || token == "" {
			log.Printf("Worker: Invalid email change payload: email=%q, token=%q", email, token)
			continue
		}

		retries := 0
		if r, ok := payload["retries"].(float64); ok {
			retries = int(r)
		}

		if err := w.sendEmailChangeNotification(email, token, emailType); err != nil {
			log.Printf("Worker: Failed to send email change notification to %s (attempt %d): %v", email, retries+1, err)
			if retries >= maxEmailRetries {
				log.Printf("Worker: Permanently failed to send email change notification to %s after %d attempts", email, maxEmailRetries)
				continue
			}
			payload["retries"] = retries + 1
			newPayload, _ := json.Marshal(payload)
			delay := time.Duration(math.Pow(2, float64(retries))) * time.Second
			score := float64(time.Now().Add(delay).UnixMilli())
			_ = w.Redis.ZAdd(ctx, "email_change_delayed", redis.Z{Score: score, Member: string(newPayload)}).Err()
		}
	}
}

func (w *Worker) sendEmailChangeNotification(email, token, emailType string) error {
	subject := "Confirm Your Email Change"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	body := fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Please click the link below to confirm your new email address:</p><p><a href=\"%s/confirm-email-change?token=%s\">%s/confirm-email-change?token=%s</a></p></div>", baseURL, token, baseURL, token)
	return w.Mailer.SendEmail(email, subject, body)
}

func (w *Worker) sendVerificationEmail(email, token string) error {
	subject := "Verify Your Email Address"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	body := fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Welcome to Vulfixx! Please click the link below to verify your email address:</p><p><a href=\"%s/verify-email?token=%s\">%s/verify-email?token=%s</a></p></div>", baseURL, token, baseURL, token)
	return w.Mailer.SendEmail(email, subject, body)
}

