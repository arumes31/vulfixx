## 2026-05-26 - Optimized Worker Health Check N+1 Query
**Performance Issue:** N+1 Query in `checkWorkerHealth`.
**Learning:** Checking health for multiple tasks in a loop using `QueryRow` causes multiple database roundtrips.
**Optimization:** Replaced loop-based queries with a single `ANY($1)` query to fetch all task stats at once.
**Impact:** Reduced database queries from 6+ to 1 per health check run.
## 2024-05-27 - Optimized Dashboard CVE N+1 Query
**Performance Issue:** N+1 Query in `fetchPublicDashboardCVEs` and `DashboardHandler`.
**Learning:** Fetching `cisa_ransomware` via `QueryRow` iteratively inside a `rows.Next()` loop causes N database roundtrips, degrading dashboard rendering speed.
**Optimization:** First collect all `id`s from `rows.Next()`, then execute a single batched query using `SELECT id, cisa_ransomware FROM cves WHERE id = ANY($1)`. Iterate over the batch results and map the `cisa_ransomware` flag back to the CVEs.
**Impact:** Drastically reduced dashboard database queries (eliminating the N+1 completely), accelerating the primary dashboard load.
