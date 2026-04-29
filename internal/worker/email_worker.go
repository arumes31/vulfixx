package worker

import (
	"context"
	"encoding/json"
	"errors"
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
			if !errors.Is(err, redis.Nil) {
				log.Printf("Worker: Redis error reading from verification queue: %v", err)
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
			log.Printf("Worker: Invalid email verification payload: email=%q, token=%q", maskEmail(email), redactToken(token))
			continue
		}

		retries := 0
		if r, ok := payload["retries"].(float64); ok {
			retries = int(r)
		}

		if err := w.sendVerificationEmail(email, token); err != nil {
			log.Printf("Worker: Failed to send verification email to %s (attempt %d): %v", maskEmail(email), retries+1, err)
			if retries >= maxEmailRetries {
				log.Printf("Worker: Permanently failed to send verification email to %s after %d attempts", maskEmail(email), maxEmailRetries)
				continue
			}
			payload["retries"] = retries + 1
			newPayload, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				log.Printf("Worker: Failed to marshal retry payload for %s: %v", maskEmail(email), marshalErr)
				continue
			}
			delay := time.Duration(math.Pow(2, float64(retries))) * time.Second
			score := float64(time.Now().Add(delay).UnixMilli())
			if zErr := w.Redis.ZAdd(ctx, "email_verification_delayed", redis.Z{Score: score, Member: string(newPayload)}).Err(); zErr != nil {
				log.Printf("Worker: Failed to enqueue verification retry for %s: %v", maskEmail(email), zErr)
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
			if !errors.Is(err, redis.Nil) {
				log.Printf("Worker: Redis error reading from email change queue: %v", err)
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
			log.Printf("Worker: Invalid email change payload: email=%q, token=%q", maskEmail(email), redactToken(token))
			continue
		}

		retries := 0
		if r, ok := payload["retries"].(float64); ok {
			retries = int(r)
		}

		if err := w.sendEmailChangeNotification(email, token, emailType); err != nil {
			log.Printf("Worker: Failed to send email change notification to %s (attempt %d): %v", maskEmail(email), retries+1, err)
			if retries >= maxEmailRetries {
				log.Printf("Worker: Permanently failed to send email change notification to %s after %d attempts", maskEmail(email), maxEmailRetries)
				continue
			}
			payload["retries"] = retries + 1
			newPayload, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				log.Printf("Worker: Failed to marshal retry payload for %s: %v", maskEmail(email), marshalErr)
				continue
			}
			delay := time.Duration(math.Pow(2, float64(retries))) * time.Second
			score := float64(time.Now().Add(delay).UnixMilli())
			if zErr := w.Redis.ZAdd(ctx, "email_change_delayed", redis.Z{Score: score, Member: string(newPayload)}).Err(); zErr != nil {
				log.Printf("Worker: Failed to enqueue email change retry for %s: %v", maskEmail(email), zErr)
			}
		}
	}
}

func (w *Worker) sendEmailChangeNotification(email, token, emailType string) error {
	subject := "Confirm Your Email Change"
	body := ""
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	encodedToken := url.QueryEscape(token)
	link := fmt.Sprintf("%s/confirm-email-change?token=%s", baseURL, encodedToken)

	switch emailType {
	case "old":
		subject = "Security Alert: Email Change Requested"
		body = fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>A request was made to change the email address for your Vulfixx account. If you did not make this request, please secure your account immediately.</p><p>To confirm this change from your current address, click here: <a href=\"%s\">%s</a></p></div>", link, link)
	case "new":
		subject = "Confirm Your New Email Address"
		body = fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Please click the link below to confirm your new email address for Vulfixx:</p><p><a href=\"%s\">%s</a></p></div>", link, link)
	default:
		body = fmt.Sprintf("<div style=\"font-family: sans-serif;\"><p>Please click the link below to confirm your email change for Vulfixx:</p><p><a href=\"%s\">%s</a></p></div>", link, link)
	}

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

func (w *Worker) startEmailRetryPoller(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pollDelayedQueue(ctx, "email_verification_delayed", "email_verification_queue")
			w.pollDelayedQueue(ctx, "email_change_delayed", "email_change_queue")
		}
	}
}

func (w *Worker) pollDelayedQueue(ctx context.Context, delayedQueue, activeQueue string) {
	now := float64(time.Now().UnixMilli())
	opt := &redis.ZRangeBy{
		Min: "-inf",
		Max: fmt.Sprintf("%f", now),
	}

	// Fetch due items
	items, err := w.Redis.ZRangeByScore(ctx, delayedQueue, opt).Result()
	if err != nil {
		log.Printf("Worker: Error fetching from %s: %v", delayedQueue, err)
		return
	}

	for _, item := range items {
		// Use Lua script for atomic move to prevent dropping items
		script := `
			if redis.call("ZREM", KEYS[1], ARGV[1]) > 0 then
				return redis.call("LPUSH", KEYS[2], ARGV[1])
			end
			return 0
		`
		_, err := w.Redis.Eval(ctx, script, []string{delayedQueue, activeQueue}, item).Result()
		if err != nil {
			log.Printf("Worker: Error atomically moving item from %s to %s: %v", delayedQueue, activeQueue, err)
		}
	}
}
