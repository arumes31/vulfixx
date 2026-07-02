## 2026-07-02 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-02 - Add index on secondary column of unique constraints
**Learning:** In PostgreSQL, querying a table using only the secondary column of a multi-column UNIQUE constraint (e.g., `UNIQUE(user_id, cve_id)` queried via `WHERE cve_id = $1`) results in a full sequential scan because the index is built primarily on the first column. This causes severe N+1 latency bottlenecks during batch operations like `evaluateSubscriptions`.
**Action:** Always create a dedicated single-column index for the secondary column of a multi-column constraint if the application logic frequently queries by that column independently.
