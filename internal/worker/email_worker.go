package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

const maxEmailRetries = 5

func (w *Worker) processEmailVerification(ctx context.Context) {
	for {
		// Use a short 1s timeout (not 0) so the loop can check ctx cancellation regularly.
		result, err := w.Redis.BRPop(ctx, 1*time.Second, "email_verification_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
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
			newPayload, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				log.Printf("Worker: Failed to marshal retry payload for %s: %v", email, marshalErr)
				continue
			}
			delay := time.Duration(math.Pow(2, float64(retries))) * time.Second
			score := float64(time.Now().Add(delay).UnixMilli())
			if zErr := w.Redis.ZAdd(ctx, "email_verification_delayed", redis.Z{Score: score, Member: string(newPayload)}).Err(); zErr != nil {
				log.Printf("Worker: Failed to enqueue verification retry for %s: %v", email, zErr)
			}
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
			newPayload, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				log.Printf("Worker: Failed to marshal retry payload for %s: %v", email, marshalErr)
				continue
			}
			delay := time.Duration(math.Pow(2, float64(retries))) * time.Second
			score := float64(time.Now().Add(delay).UnixMilli())
			if zErr := w.Redis.ZAdd(ctx, "email_change_delayed", redis.Z{Score: score, Member: string(newPayload)}).Err(); zErr != nil {
				log.Printf("Worker: Failed to enqueue email change retry for %s: %v", email, zErr)
			}
		}
	}
}

func (w *Worker) sendEmailChangeNotification(email, token, emailType string) error {
	subject := "Confirm Your Email Change"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	encodedToken := url.QueryEscape(token)
	link := fmt.Sprintf("%s/confirm-email-change?token=%s", baseURL, encodedToken)
	body := fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Please click the link below to confirm your new email address:</p><p><a href=\"%s\">%s</a></p></div>", link, link)
	return w.Mailer.SendEmail(email, subject, body)
}

func (w *Worker) sendVerificationEmail(email, token string) error {
	subject := "Verify Your Email Address"
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	encodedToken := url.QueryEscape(token)
	link := fmt.Sprintf("%s/verify-email?token=%s", baseURL, encodedToken)
	body := fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Welcome to Vulfixx! Please click the link below to verify your email address:</p><p><a href=\"%s\">%s</a></p></div>", link, link)
	return w.Mailer.SendEmail(email, subject, body)
}
