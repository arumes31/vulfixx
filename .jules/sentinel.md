## 2025-02-14 - IP Spoofing via X-Forwarded-For
**Vulnerability:** The application blindly trusted the first IP address in the `X-Forwarded-For` header to determine the client's IP, making it vulnerable to IP spoofing if a malicious user provided a comma-separated list of fake IPs.
**Learning:** `X-Forwarded-For` headers can be easily spoofed by the client. Simply picking the first IP without validating the trust chain exposes the application to rate limit bypasses and spoofed audit logs.
**Prevention:** Always iterate the `X-Forwarded-For` list from right-to-left, stopping at the first untrusted proxy, to correctly identify the true client IP.
