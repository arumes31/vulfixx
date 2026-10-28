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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "invalid healthcheck port %q\n", port)
		os.Exit(1)
	}
	healthURL := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", strconv.FormatUint(portNumber, 10)),
		Path:   "/healthz",
	}
	client := &http.Client{Timeout: 2 * time.Second}
	// #nosec G704 -- the destination is a fixed loopback address with a validated numeric port.
	response, err := client.Get(healthURL.String())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck request: %v\n", err)
		os.Exit(1)
	}
	if err := response.Body.Close(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "close healthcheck response: %v\n", err)
		os.Exit(1)
	}
	if response.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(os.Stderr, "healthcheck returned %s\n", response.Status)
		os.Exit(1)
	}
}
