## 2025-02-24 - [CRITICAL] Fix IP Spoofing via Right-to-Left X-Forwarded-For Iteration
**Vulnerability:** IP Spoofing
**Learning:** `X-Forwarded-For` header lists are appended to by intermediate proxies. Naively selecting the left-most IP (`ips[0]`) allows an attacker to inject a spoofed IP, which intermediate proxies will merely append the actual IP to. This bypasses rate-limiting and leaves inaccurate audit logs.
**Prevention:** Always iterate through the `X-Forwarded-For` list from right to left, skipping known trusted proxies, and treating the first untrusted IP encountered as the true client IP.
