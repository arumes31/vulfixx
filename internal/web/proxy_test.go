package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func TestIsTrustedProxy(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies string
		ip             string
		want           bool
	}{
		{"DefaultTrustLoopbackIPv4", "", "127.0.0.1", true},
		{"DefaultTrustLoopbackIPv6", "", "::1", true},
		{"DefaultRejectPublicIPv4", "", "1.1.1.1", false},
		{"CIDRMatch", "10.0.0.0/8", "10.0.0.1", true},
		{"CIDRNoMatch", "10.0.0.0/8", "11.0.0.1", false},
		{"SpecificIPMatch", "192.168.1.1", "192.168.1.1", true},
		{"SpecificIPNoMatch", "192.168.1.1", "192.168.1.2", false},
		{"MultipleProxiesCIDR", "10.0.0.0/8,192.168.1.0/24", "10.0.0.1", true},
		{"MultipleProxiesIP", "10.0.0.0/8,192.168.1.1", "192.168.1.1", true},
		{"MalformedEnv", " , ,10.0.0.1", "10.0.0.1", true},
		{"InvalidIPInput", "10.0.0.0/8", "not-an-ip", false},
		{"InvalidCIDREnv", "invalid-cidr/99", "10.0.0.1", false},
		{"IPv6Match", "2001:db8::/32", "2001:db8::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", tt.trustedProxies)
			if got := isTrustedProxy(tt.ip); got != tt.want {
				t.Errorf("isTrustedProxy(%q) = %v, want %v (TRUSTED_PROXIES=%q)", tt.ip, got, tt.want, tt.trustedProxies)
			}
		})
	}
}

func TestProxyMiddleware_Detailed(t *testing.T) {
	mock, _ := pgxmock.NewPool()
	defer mock.Close()
	app := setupTestApp(t, mock)

	tests := []struct {
		name             string
		remoteAddr       string
		headers          map[string]string
		enableCF         string
		trustedProxies   string
		expectedClientIP string
	}{
		{
			name:             "RemoteAddrNoPort",
			remoteAddr:       "127.0.0.1",
			expectedClientIP: "127.0.0.1",
		},
		{
			name:             "XRealIPFallback",
			remoteAddr:       "127.0.0.1:1234",
			headers:          map[string]string{"X-Real-IP": "2.2.2.2"},
			trustedProxies:   "127.0.0.1",
			expectedClientIP: "2.2.2.2",
		},
		{
			name:             "CFMissingHeaderFallbackToXFF",
			remoteAddr:       "127.0.0.1:1234",
			headers:          map[string]string{"X-Forwarded-For": "3.3.3.3"},
			enableCF:         "true",
			trustedProxies:   "127.0.0.1",
			expectedClientIP: "3.3.3.3",
		},
		{
			name:             "CFNotTrusted",
			remoteAddr:       "1.1.1.1:1234",
			headers:          map[string]string{"CF-Connecting-IP": "2.2.2.2"},
			enableCF:         "true",
			trustedProxies:   "127.0.0.1",
			expectedClientIP: "1.1.1.1",
		},
		{
			name:             "IPv6Request",
			remoteAddr:       "[::1]:1234",
			headers:          map[string]string{"X-Forwarded-For": "2001:db8::1"},
			trustedProxies:   "::1",
			expectedClientIP: "2001:db8::1",
		},
		{
			name:             "UntrustedXFF",
			remoteAddr:       "1.1.1.1:1234",
			headers:          map[string]string{"X-Forwarded-For": "2.2.2.2"},
			trustedProxies:   "127.0.0.1",
			expectedClientIP: "1.1.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENABLE_CLOUDFLARE_PROXY", tt.enableCF)
			t.Setenv("TRUSTED_PROXIES", tt.trustedProxies)

			var capturedIP string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if val := r.Context().Value(clientIPKey); val != nil {
					capturedIP = val.(string)
				}
				w.WriteHeader(http.StatusOK)
			})

			middleware := app.ProxyMiddleware(next)
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()

			middleware.ServeHTTP(rr, req)

			if capturedIP != tt.expectedClientIP {
				t.Errorf("expected client IP %s, got %s", tt.expectedClientIP, capturedIP)
			}
		})
	}
}
