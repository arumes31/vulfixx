package web

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"cve-tracker/internal/config"

	"github.com/pashagolub/pgxmock/v3"
)

func TestNewServer(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	t.Run("Success", func(t *testing.T) {
		cfg := &config.Config{
			AppPort:  "0", // random free port
			GRPCPort: "0", // random free port
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		srv, err := NewServer(cfg, handler, mock)
		if err != nil {
			t.Fatalf("expected NewServer to succeed, got: %v", err)
		}
		if srv == nil {
			t.Fatalf("expected non-nil Server")
		}
		srv.grpcServer.GracefulStop()
	})

	t.Run("gRPCStartupFailure", func(t *testing.T) {
		cfg := &config.Config{
			AppPort:  "0",
			GRPCPort: "999999", // invalid port format to force net.Listen to fail
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		_, err := NewServer(cfg, handler, mock)
		if err == nil {
			t.Error("expected NewServer to fail on invalid gRPC port, got nil")
		}
	})
}

func TestServer_StartAndShutdown(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	cfg := &config.Config{
		AppPort:  "0", // random free port
		GRPCPort: "0", // random free port
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv, err := NewServer(cfg, handler, mock)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Allow server time to spin up
	time.Sleep(100 * time.Millisecond)

	// Shutdown the server gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	err = srv.Shutdown(shutdownCtx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	cancel()
	select {
	case startErr := <-errCh:
		if startErr != nil {
			t.Errorf("Start returned unexpected error: %v", startErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("timed out waiting for Start to exit after Shutdown")
	}
}

func TestServer_StartHTTPFailure(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock: %v", err)
	}
	defer mock.Close()

	// Manually listen on a local port to make httpServer fail to bind/listen on the same port
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to manually listen on port: %v", err)
	}
	defer lis.Close()

	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	cfg := &config.Config{
		AppPort:  port, // same port as manually listening
		GRPCPort: "0",
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv, err := NewServer(cfg, handler, mock)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	errCh := make(chan error, 1)

	go func() {
		errCh <- srv.Start(ctx)
	}()

	select {
	case startErr := <-errCh:
		if startErr == nil {
			t.Error("expected HTTP server startup to fail because port is already bound, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for HTTP server startup failure")
	}
}
