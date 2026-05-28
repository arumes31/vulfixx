## 2026-05-28 - [Optimizing GitHub Buzz Sync with Concurrent Workers]
**Learning:** Replacing synchronous HTTP requests in a loop with a concurrent worker pool and `rate.Limiter` significantly improves throughput while respecting API constraints.
**Action:** Use `golang.org/x/time/rate` to manage rate limits in background worker tasks that interact with external APIs.
