## 2026-07-11 - Prevent IP Spoofing via Middleware

**Vulnerability:** The application used `middleware.RealIP` alongside a custom `ProxyMiddleware`. `middleware.RealIP` blindly trusts `X-Forwarded-For` and `X-Real-IP` headers without validating the source IP against trusted proxies. This allowed attackers to spoof their IP address, potentially bypassing IP-based rate limiting, altering logs, and circumventing security controls.
**Learning:** Having multiple middlewares that parse client IPs can introduce conflicts or vulnerabilities. `middleware.RealIP` is explicitly deprecated and unsafe because it does not enforce a trusted proxy list.
**Prevention:** Do not use `middleware.RealIP`. Instead, use a custom middleware like `ProxyMiddleware` that strictly checks the incoming connection's remote IP against a configured list of trusted proxies (like Cloudflare or an internal load balancer) before parsing any `X-Forwarded-*` headers.
