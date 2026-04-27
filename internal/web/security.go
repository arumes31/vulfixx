package web

import "net/http"

// SecurityHeadersMiddleware adds standard HTTP security headers to all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:;")

		next.ServeHTTP(w, r)
	})
}
