## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-09 - Add single-column indexes for secondary UNIQUE constraint columns
**Learning:** When querying a table by a secondary column of a multi-column UNIQUE constraint (e.g. `UNIQUE(user_id, cve_id)` queried via `WHERE cve_id = $1`), PostgreSQL does not use the unique index, resulting in a sequential scan.
**Action:** Ensure a dedicated single-column index exists for any secondary column used in a WHERE clause to prevent sequential scans and optimize query performance.
