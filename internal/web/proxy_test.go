package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestProxyMiddleware(t *testing.T) {
	os.Setenv("TRUSTED_PROXIES", "127.0.0.1, 10.0.0.0/8, 192.168.1.100")
	defer os.Unsetenv("TRUSTED_PROXIES")

	app := &App{}

	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		xri            string
		cfIP           string
		enableCF       string
		expectedClient string
	}{
		{
			name:           "No proxy",
			remoteAddr:     "192.168.1.50:1234",
			xff:            "8.8.8.8",
			expectedClient: "192.168.1.50",
		},
		{
			name:           "Trusted proxy single XFF",
			remoteAddr:     "10.0.0.5:1234",
			xff:            "203.0.113.1",
			expectedClient: "203.0.113.1",
		},
		{
			name:           "Trusted proxy multiple XFF spoofing attempt",
			remoteAddr:     "10.0.0.5:1234",
			xff:            "spoofed_ip, 203.0.113.1, 10.0.0.1",
			expectedClient: "203.0.113.1",
		},
		{
			name:           "Trusted proxy all proxies in XFF",
			remoteAddr:     "10.0.0.5:1234",
			xff:            "127.0.0.1, 192.168.1.100, 10.0.0.1",
			expectedClient: "127.0.0.1",
		},
		{
			name:           "Trusted proxy Cloudflare",
			remoteAddr:     "10.0.0.5:1234",
			cfIP:           "203.0.113.1",
			enableCF:       "true",
			expectedClient: "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENABLE_CLOUDFLARE_PROXY", tt.enableCF)
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}
			if tt.cfIP != "" {
				req.Header.Set("CF-Connecting-IP", tt.cfIP)
			}

			rr := httptest.NewRecorder()
			var gotClientIP string
			handler := app.ProxyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotClientIP = r.Context().Value(clientIPKey).(string)
			}))

			handler.ServeHTTP(rr, req)

			if gotClientIP != tt.expectedClient {
				t.Errorf("ProxyMiddleware() ClientIP = %v, want %v", gotClientIP, tt.expectedClient)
			}
		})
	}
}
