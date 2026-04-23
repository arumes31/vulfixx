## 2025-04-22 - [Add Security Headers]
**Vulnerability:** Missing standard HTTP security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-XSS-Protection) across all responses, leaving the application slightly more vulnerable to clickjacking, MIME-sniffing, and downgrade attacks.
**Learning:** The application was using gorilla/mux and had a proxy middleware, but lacked a generic middleware for enforcing security headers.
**Prevention:** Added a `SecurityHeadersMiddleware` that gets applied to the global router in `cmd/cve-tracker/main.go` to ensure all responses get standard protection.
