package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	DefaultPort        = "8080"
	HealthCheckHost    = "127.0.0.1"
	HealthCheckPath    = "/healthz"
	HealthCheckTimeout = 2 * time.Second
)

func main() {
	if err := runMain(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func runMain() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return fmt.Errorf("invalid healthcheck port %q", port)
	}
	healthURL := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(HealthCheckHost, strconv.FormatUint(portNumber, 10)),
		Path:   HealthCheckPath,
	}
	client := &http.Client{Timeout: HealthCheckTimeout}
	// #nosec G704 -- the destination is a fixed loopback address with a validated numeric port.
	response, err := client.Get(healthURL.String())
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close healthcheck response: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned %s", response.Status)
	}
	return nil
}
