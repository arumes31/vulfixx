## 2026-05-26 - Optimized Worker Health Check N+1 Query
**Performance Issue:** N+1 Query in `checkWorkerHealth`.
**Learning:** Checking health for multiple tasks in a loop using `QueryRow` causes multiple database roundtrips.
**Optimization:** Replaced loop-based queries with a single `ANY($1)` query to fetch all task stats at once.
**Impact:** Reduced database queries from 6+ to 1 per health check run.

## 2026-05-27 - Fixed Synchronous Blocking Sleep inside Database Row Iteration
**Learning:** Sleeping (e.g., for backoff) while iterating over database `Rows` holds a connection from the pool for the duration of the sleep, leading to potential connection exhaustion.
**Action:** Load database rows into an in-memory slice and close the `Rows` iterator immediately before starting the processing loop that contains sleep/backoff logic.
