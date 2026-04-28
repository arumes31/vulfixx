## 2025-04-22 - [Add Security Headers]
**Vulnerability:** Missing standard HTTP security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-XSS-Protection) across all responses, leaving the application slightly more vulnerable to clickjacking, MIME-sniffing, and downgrade attacks.
**Learning:** The application was using gorilla/mux and had a proxy middleware, but lacked a generic middleware for enforcing security headers.
**Prevention:** Added a `SecurityHeadersMiddleware` that gets applied to the global router in `cmd/cve-tracker/main.go` to ensure all responses get standard protection.
## 2024-05-25 - Prevent DNS Rebinding / TOCTOU SSRF
**Vulnerability:** DNS Rebinding / Time-Of-Check to Time-Of-Use (TOCTOU) Server-Side Request Forgery (SSRF) in webhook alerts.
**Learning:** `net.DefaultResolver.LookupNetIP` was used to resolve IPs and check for safe IPs before launching an `http.Client`. However, the `http.Client` does its own separate DNS resolution at connection time. An attacker could exploit this gap by changing the DNS record to point to a private IP like 127.0.0.1 after the initial check passed. Also, when fixing this by using a custom `http.Transport`, one must call `defer transport.CloseIdleConnections()` to prevent FD leaks due to idle pooled connections when instantiating transports repeatedly.
**Prevention:** Use a custom `net.Dialer` with a `Control` hook when instantiating the `http.Client`. This allows inspecting and validating the exact resolved IP precisely when the connection is being established, eliminating the TOCTOU window. Also remember to close idle connections when using custom `http.Transport` instances to prevent resource leaks.

## 2026-04-28 - Missing dummy bcrypt check in login (Timing Attack)
**Vulnerability:** The `Login` function in `internal/auth/auth.go` returned early when a user was not found by email, allowing an attacker to determine if an email exists in the database by measuring the time taken for the login request (the presence of a user would cause a slow bcrypt hash comparison).
**Learning:** The application mitigated brute-forcing but failed to account for user enumeration through timing side-channels, as the bcrypt evaluation was conditional on the user existing.
**Prevention:** Always perform a constant-time check or a dummy compute-intensive operation (like checking against a static `dummyHash`) when early-exiting on authentication failures where computation time depends on data existence.
