## 2026-06-30 - Fix IP spoofing vulnerability in Proxy Middleware
**Vulnerability:** X-Forwarded-For was incorrectly parsing the IP by taking the first IP in the list instead of iterating backwards from the rightmost untrusted IP. This allowed IP spoofing since `clientIP = strings.TrimSpace(ips[0])` grabs the leftmost, user-controlled IP.
**Learning:** `X-Forwarded-For` appends IPs to the right as it passes through proxies. Always read the list from right to left, stopping at the first untrusted proxy to accurately identify the true client IP and prevent spoofing.
**Prevention:** Implement right-to-left parsing of `X-Forwarded-For` headers and explicitly check each IP against the trusted proxy list before accepting it.
