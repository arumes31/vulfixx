package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type healthRoundTripper func(*http.Request) (*http.Response, error)

func (f healthRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type healthResponseBody struct {
	io.Reader
	closeError error
	closed     bool
}

func (b *healthResponseBody) Close() error {
	b.closed = true
	return b.closeError
}

func TestRunMainPreservesHealthcheckFailures(t *testing.T) {
	requestError := errors.New("request failed")
	closeError := errors.New("response close failed")
	for _, tc := range []struct {
		name, port string
		status     int
		requestErr error
		closeErr   error
		wantErr    error
		wantText   string
		wantCall   bool
	}{
		{name: "healthy", port: "9000", status: 200, wantCall: true},
		{name: "default port", status: 200, wantCall: true},
		{name: "invalid port", port: "invalid", wantText: "invalid healthcheck port"},
		{name: "zero port", port: "0", wantText: "invalid healthcheck port"},
		{name: "overflow port", port: "65536", wantText: "invalid healthcheck port"},
		{name: "request failure", port: "9000", requestErr: requestError, wantErr: requestError, wantCall: true},
		{name: "unhealthy status", port: "9000", status: 503, wantText: "healthcheck returned 503", wantCall: true},
		{name: "close failure", port: "9000", status: 200, closeErr: closeError, wantErr: closeError, wantCall: true},
		{name: "close failure precedes status", port: "9000", status: 503, closeErr: closeError, wantErr: closeError, wantCall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PORT", tc.port)
			body := &healthResponseBody{Reader: strings.NewReader("ok"), closeError: tc.closeErr}
			called := false
			previous := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = previous })
			http.DefaultTransport = healthRoundTripper(func(r *http.Request) (*http.Response, error) {
				called = true
				port := tc.port
				if port == "" {
					port = "8080"
				}
				if r.URL.String() != "http://127.0.0.1:"+port+"/healthz" {
					t.Fatalf("unexpected request URL %s", r.URL)
				}
				if tc.requestErr != nil {
					return nil, tc.requestErr
				}
				return &http.Response{StatusCode: tc.status, Status: fmt.Sprintf("%d Test", tc.status), Body: body, Header: make(http.Header)}, nil
			})
			err := runMain()
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("error = %v, want wrapped %v", err, tc.wantErr)
				}
			case tc.wantText != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantText) {
					t.Errorf("error = %v, want %q", err, tc.wantText)
				}
			case err != nil:
				t.Errorf("healthy response failed: %v", err)
			}
			if called != tc.wantCall {
				t.Errorf("transport called = %v, want %v", called, tc.wantCall)
			}
			if called && tc.requestErr == nil && !body.closed {
				t.Error("response body was not closed")
			}
		})
	}
}
