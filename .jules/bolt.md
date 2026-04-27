## 2024-04-25 - Caching global CVE counts in RenderTemplate
**Learning:** The `RenderTemplate` function, which is called on almost every page load to render the sidebar/navbar, was executing two unconditional `SELECT COUNT(*)` queries on the `cves` table. This is a classic N+1 problem at the template rendering layer that causes significant database load as the CVE database grows.
**Action:** Implemented a global, thread-safe in-memory cache (`globalCVEStatsCache` with `sync.RWMutex`) with a 5-minute TTL. Next time, always check if global layout data fetched in a central rendering function can be cached instead of queried per-request.
## 2024-04-27 - N+1 query in worker alerts
**Learning:** `notifyIfNew` in the background worker executed a database query to re-fetch a CVE that was already fetched in the caller loop (`processAlerts` -> `evaluateSubscriptions`), causing an N+1 problem on every matching alert subscription.
**Action:** When iterating over a loop to notify users or send data, ensure the payload (e.g. `models.CVE`) is fetched once outside the loop and passed down by reference, rather than queried individually per-user.
