## 2026-05-26 - Optimized Worker Health Check N+1 Query
**Performance Issue:** N+1 Query in `checkWorkerHealth`.
**Learning:** Checking health for multiple tasks in a loop using `QueryRow` causes multiple database roundtrips.
**Optimization:** Replaced loop-based queries with a single `ANY($1)` query to fetch all task stats at once.
**Impact:** Reduced database queries from 6+ to 1 per health check run.
## 2026-05-26 - Optimized Dashboard N+1 Query for cisa_ransomware
**Performance Issue:** N+1 Query in `DashboardHandler` and `fetchPublicDashboardCVEs`.
**Learning:** Fetching `cisa_ransomware` per-row inside a loop iterating over CVE records causes N+1 query execution, drastically reducing performance on dashboard views that load many CVEs. Attempting to add this boolean field to the primary 22-column `SELECT` query would have broken a significant number of `pgxmock` expectations across multiple test files.
**Optimization:** Replaced the loop-based queries with a single batched query using `id = ANY($1)`, replacing N queries with 1 query while preserving the primary query's column structure.
**Impact:** Significantly reduced database roundtrips when populating the CVE dashboard list, avoiding N extra database hits.
