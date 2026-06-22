package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"cve-tracker/internal/config"
	"cve-tracker/internal/db"

	"google.golang.org/grpc"
)

// Server encapsulates HTTP and gRPC server lifecycle.
type Server struct {
	httpServer *http.Server
	grpcServer *grpc.Server
	appPort    string
}

// NewServer initializes both HTTP and gRPC servers.
func NewServer(cfg *config.Config, handler http.Handler, pool db.DBPool) (*Server, error) {
	httpServer := &http.Server{
		Addr:              ":" + cfg.AppPort,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	grpcServer, err := StartGRPCServer(pool, cfg.GRPCPort, cfg.GRPCCertFile, cfg.GRPCKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to start gRPC server: %w", err)
	}

	return &Server{
		httpServer: httpServer,
		grpcServer: grpcServer,
		appPort:    cfg.AppPort,
	}, nil
}

// Start starts both servers and handles the blocking select on context cancellation or startup errors.
func (s *Server) Start(ctx context.Context) error {
	startupErrCh := make(chan error, 1)
	go func() {
		slog.Info("Listening", "port", s.appPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			startupErrCh <- err
		}
	}()

	for {
		select {
		case err := <-startupErrCh:
			slog.Error("HTTP server failed to start", "error", err)
			s.grpcServer.GracefulStop()
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

// Shutdown gracefully stops both servers.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("Shutting down gracefully...")

	s.grpcServer.GracefulStop()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	slog.Info("Server stopped.")
	return nil
}
