## 2024-06-22 - Fix insecure Client IP parsing via X-Forwarded-For
**Vulnerability:** The proxy middleware incorrectly extracted the client IP from the `X-Forwarded-For` header by taking the first (left-most) IP. In an `X-Forwarded-For` chain, the left-most IP can be spoofed by a malicious client.
**Learning:** When extracting the client IP from a list of proxies, evaluate from right to left, stopping at the first untrusted proxy. This ensures that only IPs added by trusted infrastructure are trusted.
**Prevention:** Iterating right to left and checking against a trusted proxy configuration block ensures that the application doesn't accidentally trust a client-provided spoofed IP as the actual client IP.
