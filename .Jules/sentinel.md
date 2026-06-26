## 2024-06-26 - [Proxy Middleware IP Spoofing Fix]
**Vulnerability:** X-Forwarded-For header spoofing vulnerability.
**Learning:** The proxy middleware previously extracted the leftmost IP from the `X-Forwarded-For` header. Because the leftmost IP can be arbitrarily spoofed by an attacker, this is insecure.
**Prevention:** Always iterate through the `X-Forwarded-For` header from right-to-left, stopping at the first untrusted proxy. This ensures that the application identifies the correct client IP regardless of spoofed entries injected by the attacker.
