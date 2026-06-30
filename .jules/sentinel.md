
## 2024-05-18 - Fix IP Spoofing in Proxy Middleware
**Vulnerability:** The application blindly trusted the first IP in the `X-Forwarded-For` header. An attacker could spoof their IP by sending a request with a fake `X-Forwarded-For` header, which would be prepended by the actual proxy. Since the code just took the first element, it used the spoofed IP.
**Learning:** `X-Forwarded-For` parsing must evaluate proxies right-to-left. You can only trust an IP if the previous hop was a trusted proxy.
**Prevention:** Always iterate backwards over the `X-Forwarded-For` list, stopping at the first untrusted proxy. Never blindly take `ips[0]`.
