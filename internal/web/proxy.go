package web

import (
	"context"
	"net/http"
	"os"
	"strings"
)

type contextKey string

const clientIPKey contextKey = "ClientIP"

func ProxyMiddleware(next http.Handler) http.Handler {
	enableCF := os.Getenv("ENABLE_CLOUDFLARE_PROXY") == "true"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr // fallback

		if enableCF {
			if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
				clientIP = cfIP
			}
		}

		// Only parse X-Forwarded-For / X-Real-IP if not using CF header
		if clientIP == r.RemoteAddr {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ips := strings.Split(xff, ",")
				if len(ips) > 0 {
					clientIP = strings.TrimSpace(ips[0])
				}
			} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
				clientIP = xri
			}
		}

		ctx := context.WithValue(r.Context(), clientIPKey, clientIP)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
