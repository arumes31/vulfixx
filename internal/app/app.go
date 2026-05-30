package app

import (
	"context"
	"cve-tracker/internal/auth"
	"cve-tracker/internal/config"
	"cve-tracker/internal/db"
	"cve-tracker/internal/web"
	"cve-tracker/internal/worker"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
)

// App encapsulates the application lifecycle and dependencies.
type App struct {
	cfg *config.Config
}

// New creates a new App instance with the given configuration.
func New(cfg *config.Config) *App {
	return &App{cfg: cfg}
}

// Run bootstraps and starts the application, blocking until the context is cancelled
// or a termination signal is received.
func (a *App) Run(ctx context.Context) error {
	slog.Info("Starting CVE Tracker...")

	// Listen for interrupt/termination signals
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize Database
	if err := db.InitDB(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.CloseDB()

	// Initialize Redis
	if err := db.InitRedis(); err != nil {
		return fmt.Errorf("failed to initialize redis: %w", err)
	}
	defer db.CloseRedis()

	// Initialize Session Store
	if _, err := web.InitRedisSession(db.RedisClient, []byte(a.cfg.SessionKey), a.cfg.SecureCookie); err != nil {
		slog.Warn("Failed to initialize Redis-backed session store, falling back to CookieStore", "error", err)
		web.InitSession([]byte(a.cfg.SessionKey), a.cfg.SecureCookie)
	} else {
		slog.Info("Redis-backed session store initialized successfully.")
	}

	// Initialize Mailer and Web App
	mailer := worker.NewEmailSender(a.cfg.SMTPHost, fmt.Sprintf("%d", a.cfg.SMTPPort), a.cfg.SMTPUser, a.cfg.SMTPPass, a.cfg.SMTPMailFrom)
	webapp := web.NewApp(db.Pool, db.RedisClient, web.GetSessionStore(), mailer)
	webapp.InitTemplates()

	// Initialize Asynq Client for decoupled background tasks
	asynqConn := worker.GetAsynqRedisConnOpt()
	asynqClient := asynq.NewClient(asynqConn)
	defer asynqClient.Close()
	webapp.AsynqClient = asynqClient

	// Initialize Admin User
	if err := auth.InitAdmin(ctx, a.cfg.AdminEmail, a.cfg.AdminPassword, a.cfg.AdminTOTPSecret); err != nil {
		return fmt.Errorf("failed to initialize admin: %w", err)
	}

	// Initialize and Start Background Worker
	wrk := worker.NewWorker(db.Pool, db.RedisClient, mailer, &http.Client{Timeout: 120 * time.Second})
	wrk.AdminEmail = a.cfg.AdminEmail
	wrk.WebhookSecret = a.cfg.WebhookSecret
	wrk.AsynqClient = asynqClient
	go wrk.Start(ctx)

	// Initialize Router and Server
	handler, err := webapp.Routes(a.cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize routes: %w", err)
	}

	srv, err := web.NewServer(a.cfg, handler, db.Pool)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Start Server
	go func() {
		if err := srv.Start(ctx); err != nil {
			slog.Error("Server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}
