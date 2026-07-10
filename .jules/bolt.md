## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2024-07-10 - Missing Index on Secondary Column of UNIQUE Constraint
**Learning:** In PostgreSQL, a multi-column UNIQUE constraint (e.g., UNIQUE(user_id, cve_id)) automatically creates an index on both columns. However, querying by only the secondary column (WHERE cve_id = $1) will result in a sequential scan because the B-tree index is optimized for queries starting from the first column.
**Action:** Always add a dedicated single-column index for the secondary column of a multi-column constraint if that secondary column is frequently used in WHERE clauses independently.
