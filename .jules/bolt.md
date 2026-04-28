## 2024-04-25 - Caching global CVE counts in RenderTemplate
**Learning:** The `RenderTemplate` function, which is called on almost every page load to render the sidebar/navbar, was executing two unconditional `SELECT COUNT(*)` queries on the `cves` table. This is a classic N+1 problem at the template rendering layer that causes significant database load as the CVE database grows.
**Action:** Implemented a global, thread-safe in-memory cache (`globalCVEStatsCache` with `sync.RWMutex`) with a 5-minute TTL. Next time, always check if global layout data fetched in a central rendering function can be cached instead of queried per-request.

## 2024-05-01 - Avoid N+1 in worker by passing pre-fetched structures
**Learning:** Found an N+1 performance bottleneck in the background worker (`notifyIfNew`), where the database was re-queried to fetch `CVE` data for every matching alert subscription in a loop, despite the worker already possessing the `models.CVE` struct from the queue.
**Action:** Passed `*models.CVE` by reference to notification functions to avoid redundant lookups. Always pass fully populated data objects downstream instead of just IDs to avoid N+1 queries during bulk operations.
