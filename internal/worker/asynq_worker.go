package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hibiken/asynq"
)

// GetAsynqRedisConnOpt constructs the Redis connection options for Asynq based on environment variables.
func GetAsynqRedisConnOpt() asynq.RedisConnOpt {
	password := os.Getenv("REDIS_PASSWORD")
	masterName := os.Getenv("REDIS_SENTINEL_MASTER")
	if masterName != "" {
		sentinelAddrsStr := os.Getenv("REDIS_SENTINEL_ADDRS")
		if sentinelAddrsStr == "" {
			sentinelAddrsStr = os.Getenv("REDIS_URL")
		}
		if sentinelAddrsStr == "" {
			sentinelAddrsStr = "localhost:26379"
		}
		sentinelAddrs := strings.Split(sentinelAddrsStr, ",")
		for i := range sentinelAddrs {
			sentinelAddrs[i] = strings.TrimSpace(sentinelAddrs[i])
		}
		return asynq.RedisFailoverClientOpt{
			MasterName:    masterName,
			SentinelAddrs: sentinelAddrs,
			Password:      password,
		}
	}

	clusterAddrsStr := os.Getenv("REDIS_CLUSTER_ADDRS")
	if clusterAddrsStr == "" {
		clusterAddrsStr = os.Getenv("REDIS_URL")
	}

	if strings.Contains(clusterAddrsStr, ",") {
		addrs := strings.Split(clusterAddrsStr, ",")
		for i := range addrs {
			addrs[i] = strings.TrimSpace(addrs[i])
		}
		return asynq.RedisClusterClientOpt{
			Addrs:    addrs,
			Password: password,
		}
	}

	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "localhost:6379"
	}
	return asynq.RedisClientOpt{
		Addr:     url,
		Password: password,
	}
}

type asynqLogger struct{}

func (l *asynqLogger) Debug(args ...interface{}) { slog.Debug(fmt.Sprint(args...)) }
func (l *asynqLogger) Info(args ...interface{})  { slog.Info(fmt.Sprint(args...)) }
func (l *asynqLogger) Warn(args ...interface{})  { slog.Warn(fmt.Sprint(args...)) }
func (l *asynqLogger) Error(args ...interface{}) { slog.Error(fmt.Sprint(args...)) }
func (l *asynqLogger) Fatal(args ...interface{}) {
	slog.Error(fmt.Sprint(args...))
	os.Exit(1)
}

// StartAsynqServer starts the Asynq server to process decoupled jobs.
func (w *Worker) StartAsynqServer(ctx context.Context) {
	connOpt := GetAsynqRedisConnOpt()
	srv := asynq.NewServer(connOpt, asynq.Config{
		Concurrency: 10,
		Logger:      &asynqLogger{},
	})

	mux := asynq.NewServeMux()
	mux.HandleFunc("task:cve_alert", w.handleCVEAlertTask)
	mux.HandleFunc("task:email_verification", w.handleEmailVerificationTask)
	mux.HandleFunc("task:email_change", w.handleEmailChangeTask)

	slog.Info("Worker: Starting Asynq server...")
	if err := srv.Start(mux); err != nil {
		slog.Error("Worker: Asynq server failed to start", "error", err)
		return
	}

	<-ctx.Done()
	slog.Info("Worker: Shutting down Asynq server...")
	srv.Shutdown()
	slog.Info("Worker: Asynq server stopped.")
}

func (w *Worker) handleCVEAlertTask(ctx context.Context, t *asynq.Task) error {
	var cve models.CVE
	if err := json.Unmarshal(t.Payload(), &cve); err != nil {
		return fmt.Errorf("failed to unmarshal CVE: %v: %w", err, asynq.SkipRetry)
	}
	w.evaluateSubscriptions(ctx, &cve)
	return nil
}

func (w *Worker) handleEmailVerificationTask(ctx context.Context, t *asynq.Task) error {
	var payload map[string]interface{}
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal verification email payload: %v: %w", err, asynq.SkipRetry)
	}
	email, _ := payload["email"].(string)
	token, _ := payload["token"].(string)
	if email == "" || token == "" {
		return fmt.Errorf("invalid verification payload email/token: %w", asynq.SkipRetry)
	}
	if isEmailDomainBlacklisted(email) {
		slog.Warn("Worker: Blocked verification email to blacklisted domain", "email", maskEmail(email))
		return nil
	}

	if err := w.sendVerificationEmail(email, token); err != nil {
		return fmt.Errorf("failed to send verification email to %s: %w", email, err)
	}
	return nil
}

func (w *Worker) handleEmailChangeTask(ctx context.Context, t *asynq.Task) error {
	var payload map[string]interface{}
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal email change payload: %v: %w", err, asynq.SkipRetry)
	}
	email, _ := payload["email"].(string)
	token, _ := payload["token"].(string)
	emailType, _ := payload["type"].(string)
	if email == "" || token == "" {
		return fmt.Errorf("invalid email change payload email/token: %w", asynq.SkipRetry)
	}
	if isEmailDomainBlacklisted(email) {
		slog.Warn("Worker: Blocked email change notification to blacklisted domain", "email", maskEmail(email))
		return nil
	}

	if err := w.sendEmailChangeNotification(email, token, emailType); err != nil {
		return fmt.Errorf("failed to send email change notification to %s: %w", email, err)
	}
	return nil
}
