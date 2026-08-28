package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// An attacker must not be able to choose their own apparent client IP.
//
// chi's middleware.RealIP rewrites r.RemoteAddr straight from X-Forwarded-For with no
// trusted-proxy check. It used to run ahead of ProxyMiddleware, which decides whether
// to trust XFF by asking isTrustedProxy(r.RemoteAddr) — so RealIP handed the attacker
// control of the very value the trust decision was based on. Sending
// "X-Forwarded-For: 127.0.0.1" made the request look like it arrived from a trusted
// loopback proxy, unlocking the XFF parsing path and letting the caller pin their
// client IP to anything, defeating rate limiting and poisoning activity logs.
//
// This exercises the real ProxyMiddleware rather than a stand-in.
func TestProxyMiddlewareRejectsSpoofedForwardedFor(t *testing.T) {
	// Empty means "trust loopback only", the default deployment posture.
	t.Setenv("TRUSTED_PROXIES", "")

	app := &App{}

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "untrusted peer cannot claim loopback",
			remoteAddr: "203.0.113.9:51234",
			headers:    map[string]string{"X-Forwarded-For": "127.0.0.1"},
			want:       "203.0.113.9",
		},
		{
			name:       "untrusted peer cannot claim an arbitrary address",
			remoteAddr: "203.0.113.9:51234",
			headers:    map[string]string{"X-Forwarded-For": "8.8.8.8"},
			want:       "203.0.113.9",
		},
		{
			name:       "X-Real-IP is ignored from an untrusted peer",
			remoteAddr: "203.0.113.9:51234",
			headers:    map[string]string{"X-Real-IP": "127.0.0.1"},
			want:       "203.0.113.9",
		},
		{
			name:       "no headers falls back to the peer",
			remoteAddr: "198.51.100.7:4444",
			want:       "198.51.100.7",
		},
		{
			// Behind a genuinely trusted proxy the leftmost entry is still
			// attacker-supplied; the real client is the rightmost untrusted hop.
			name:       "trusted proxy: prepended spoof is ignored",
			remoteAddr: "127.0.0.1:9999",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 198.51.100.7"},
			want:       "198.51.100.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			handler := app.ProxyMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = app.GetClientIP(r)
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if got != tt.want {
				t.Errorf("client IP = %q, want %q — an attacker able to set this "+
					"chooses their own rate-limit bucket", got, tt.want)
			}
		})
	}
}

// Guards the router wiring itself. The middleware is only safe because nothing
// rewrites RemoteAddr before ProxyMiddleware inspects it.
func TestRouterDoesNotUseRealIP(t *testing.T) {
	body, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue // the explanatory comment mentions it by name
		}
		if strings.Contains(trimmed, "middleware.RealIP") {
			t.Errorf("router re-enables middleware.RealIP (%q); it rewrites RemoteAddr "+
				"from X-Forwarded-For with no trust check and lets a caller spoof their "+
				"own client IP past ProxyMiddleware", trimmed)
		}
	}
}
