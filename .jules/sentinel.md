
## 2026-06-25 - IP Spoofing via X-Forwarded-For
**Vulnerability:** The proxy middleware extracted the true client IP by taking the leftmost entry from the `X-Forwarded-For` header `ips[0]`.
**Learning:** This implementation blindly trusts user input. If an attacker injects `X-Forwarded-For: 1.1.1.1`, the proxy appends the true IP to the right, resulting in `X-Forwarded-For: 1.1.1.1, 8.8.8.8`. Taking the leftmost value allows attackers to bypass rate limits and IP blocking.
**Prevention:** Always traverse `X-Forwarded-For` headers from right to left, stopping at the first IP that is not part of a known trusted proxy network.
