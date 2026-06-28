## 2026-06-28 - [Fix IP Spoofing in X-Forwarded-For parsing]
**Vulnerability:** X-Forwarded-For IP spoofing vulnerability in proxy IP determination.
**Learning:** Parsing the first IP from `X-Forwarded-For` allows attackers to easily spoof their IP address, since they can construct their own header that prepends a fake IP. This can bypass rate limiting, geo-fencing, or logging.
**Prevention:** Always iterate the `X-Forwarded-For` header from right to left, checking against trusted proxy lists, and stop at the first IP that is not a trusted proxy.
