## 2026-06-27 - IP Spoofing via X-Forwarded-For
**Vulnerability:** The application was vulnerable to IP spoofing because it blindly trusted the first IP (`ips[0]`) in the `X-Forwarded-For` header.
**Learning:** Naively splitting a comma-separated list of IPs in an HTTP header and picking the first one allows attackers to inject arbitrary spoofed IP addresses (e.g. `X-Forwarded-For: 1.2.3.4, <their_real_ip>`), bypassing rate limits, login bans, or any security logic reliant on client IP.
**Prevention:** Always iterate through the `X-Forwarded-For` list from right-to-left. Stop as soon as an IP is encountered that is *not* a configured, trusted proxy. The first untrusted IP found reading from right-to-left is the true, spoof-proof client IP.
