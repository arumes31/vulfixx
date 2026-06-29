## 2026-06-29 - Fixed X-Forwarded-For IP Spoofing
**Vulnerability:** The application was vulnerable to IP spoofing because it trusted the first (leftmost) IP in the `X-Forwarded-For` header.
**Learning:** The leftmost IP is provided by the client and can easily be spoofed. The correct approach is to parse from right to left, stopping at the first untrusted proxy.
**Prevention:** Always iterate `X-Forwarded-For` from right to left and only trust IP addresses provided by known, trusted proxies.
