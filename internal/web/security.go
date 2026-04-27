package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

const NonceKey contextKey = "nonce"

// SecurityHeadersMiddleware adds standard HTTP security headers to all responses.
func (a *App) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateNonce()
		r = r.WithContext(context.WithValue(r.Context(), NonceKey, nonce))

		// Prevent browsers from performing MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Defend against clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Enforce HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Control referrer information
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Cross-Site Scripting protection (modern approach is CSP)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-%s'; font-src 'self' data:; img-src 'self' data:;", nonce))

		next.ServeHTTP(w, r)
	})
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
