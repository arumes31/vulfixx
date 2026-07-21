## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-21 - Optimize hot loops with pre-allocation and fast formatting
**Learning:** Using `fmt.Sprintf` inside hot loops like CSV exports incurs significant reflection overhead. Similarly, re-allocating a slice inside a loop creates unnecessary garbage collection pressure.
**Action:** Pre-allocate slices outside the loop and reuse them via index assignment. Replace reflection-based `fmt.Sprintf` with specialized functions from `strconv` (like `FormatFloat` and `FormatBool`), and use time formatting constants (`time.DateOnly`) for much faster execution.
