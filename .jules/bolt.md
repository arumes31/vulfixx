## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2024-07-01 - Add single-column index to complement UNIQUE constraint
**Learning:** PostgreSQL uses the first column of a multicolumn UNIQUE index (like UNIQUE(user_id, cve_id)) for lookups on that first column, but a query filtering only on the second column (WHERE cve_id = $1) cannot efficiently use that index, leading to sequential scans.
**Action:** When a table has a multi-column UNIQUE constraint and queries filter solely on the secondary column(s), explicitly create an additional single-column index on those secondary column(s) to maintain query performance.
