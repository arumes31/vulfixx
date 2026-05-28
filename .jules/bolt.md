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

## 2026-05-27 - Triggering csv.Writer Write Errors in Tests
**Learning:** `csv.Writer` uses a `bufio.Writer` internally (with a default buffer size of 4096 bytes). To trigger an error in the underlying `http.ResponseWriter` during a `csvWriter.Write(row)` call, the buffer must be filled or explicitly flushed.
**Action:** When testing for `Write` errors in CSV exports, either provide enough large rows to exceed the 4096-byte buffer or ensure that the error is expected at the `Flush()` call, which will attempt to push remaining buffered data.

## 2026-05-27 - Fixed Synchronous Blocking Sleep inside Database Row Iteration
**Learning:** Sleeping (e.g., for backoff) while iterating over database `Rows` holds a connection from the pool for the duration of the sleep, leading to potential connection exhaustion.
**Action:** Load database rows into an in-memory slice and close the `Rows` iterator immediately before starting the processing loop that contains sleep/backoff logic.

## 2026-05-28 - Optimized OSV Sync with Concurrent Worker Pool
**Learning:** Sequential HTTP requests in a loop cause significant latency and underutilize resources. Using a concurrent worker pool (e.g., errgroup or sync.WaitGroup with channels) allows for parallel processing of I/O-bound tasks while maintaining a controllable level of concurrency.
**Action:** Implement a worker pool pattern for loops containing synchronous HTTP requests to improve performance and throughput.
