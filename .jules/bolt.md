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

## 2026-05-28 - Combined Multiple Database COUNT Queries using PostgreSQL FILTER
**Performance Issue:** Execution of multiple single `SELECT COUNT(*)` queries for different conditions on the same table.
**Learning:** Running consecutive `SELECT COUNT(*)` queries on the same table but with different `WHERE` conditions causes multiple database roundtrips and increases latency.
**Action:** Use PostgreSQL's `FILTER` clause (e.g., `COUNT(*) FILTER (WHERE condition)`) inside a single `SELECT` statement to aggregate multiple counts in a single database roundtrip.

## 2026-05-28 - Optimized OSV Sync with Concurrent Worker Pool
**Learning:** Sequential HTTP requests in a loop cause significant latency and underutilize resources. Using a concurrent worker pool (e.g., errgroup or sync.WaitGroup with channels) allows for parallel processing of I/O-bound tasks while maintaining a controllable level of concurrency.
**Action:** Implement a worker pool pattern for loops containing synchronous HTTP requests to improve performance and throughput.

## 2026-05-28 - Refactored Overly Complex AssetsHandler to Repository Pattern
**Performance Issue:** Bloated handler logic combining request parsing, validation, database transactions, and UI rendering.
**Learning:** Consolidating complex database operations (transactions, quota checks, keyword mapping) into a dedicated Repository layer simplifies handler logic and improves testability by decoupling HTTP concerns from data persistence.
**Optimization:** Created `AssetRepository` to encapsulate SQL logic and transaction management. Split `AssetsHandler` into specialized internal methods for GET and POST.
**Impact:** Improved code readability, reduced cyclomatic complexity of the handler, and centralized asset-related database logic for reuse.

## 2026-05-28 - Parallelizing InTheWild Sync with Worker Pool
**Learning:** Sequential HTTP requests in synchronization loops cause significant latency, especially when throtlling is required for API compliance. Using a worker pool with a centralized ticker allows for controlled parallelism while strictly adhering to rate limits.
**Action:** Identify sync loops with blocking I/O and refactor them to use `errgroup` and a shared `time.Ticker` for rate-limited concurrent processing.
## 2026-05-30 - Optimized Dashboard and Ticker N+1 Queries
**Performance Issue:** Execution of multiple aggregate `COUNT(*)` queries for different conditions on the same table.
**Learning:** Running consecutive `SELECT COUNT(*) FILTER ...` queries sequentially on the same table causes multiple database roundtrips and increases latency.
**Action:** Use PostgreSQL's `FILTER` clause (`COUNT(*) FILTER (WHERE condition)`) to combine multiple separate aggregate queries into a single `SELECT` statement, fetching all required counts in one database roundtrip.

## 2026-05-30 - Optimized Database Updates in GitHub Buzz Sync
**Learning:** Performing individual `tx.Exec` calls within a transaction loop in `updateGitHubBatch` for 50 items results in 50 separate database roundtrips, which degrades performance.
**Action:** Implemented `pgx.Batch` within the transaction to send all update queries in a single database roundtrip, significantly reducing I/O latency, while maintaining a fallback loop for `pgxmock` test compatibility.
## 2026-06-13 - Optimized Redundant Database COUNT Query
**Learning:** Running an explicit `SELECT COUNT(*)` query solely to get the length of the results from a preceding identical  statement causes an unnecessary database roundtrip.
**Action:** Replaced the redundant query with `total := len(slice)` since the slice already contains exactly the bounded subset of rows from the database. Removed the associated unneeded `pgxmock.ExpectQuery` expectation in tests.
## 2026-06-13 - Optimized Redundant Database COUNT Query
**Learning:** Running an explicit SELECT COUNT(*) query solely to get the length of the results from a preceding identical SELECT statement causes an unnecessary database roundtrip.
**Action:** Replaced the redundant query with total := len(slice) since the slice already contains exactly the bounded subset of rows from the database. Removed the associated unneeded pgxmock.ExpectQuery expectation in tests.
## 2025-02-28 - Escaping Backslashes in Python Scripts for Go Code Modification
**Learning:** When using Python scripts (`cat << 'EOF' > script.py`) to search and replace Go code that contains regular expression patterns with backslashes (like `\d`), the backslashes must be properly double-escaped in Python's normal strings (e.g., `\\d`) or raw strings (e.g., `r'CVE-\d{4}'`) must be used to prevent `SyntaxWarning: invalid escape sequence` errors during script execution.
**Action:** When creating Python scripts to refactor Go source code with inline regular expressions, ensure string replacement patterns use double backslashes for escaping or raw strings to correctly output the intended Go syntax.
