## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-19 - Composite Indexes Don't Optimize Trailing Columns
**Learning:** The `alert_history` table had `UNIQUE(user_id, cve_id)`, but queries like `SELECT user_id FROM alert_history WHERE cve_id = $1` were triggering sequential scans because the leading column (`user_id`) wasn't in the WHERE clause.
**Action:** Always add explicit indexes on trailing columns of composite constraints if those columns are queried independently, especially in high-throughput worker queues.
