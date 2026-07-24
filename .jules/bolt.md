## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-24 - Optimize CSV Generation
**Learning:** Using `fmt.Sprintf` and dynamically allocating slices inside high-frequency data loops (like CSV row generation) incurs unnecessary reflection overhead and allocations.
**Action:** Always pre-allocate slices using `make([]type, size)` and assign elements by index. Replace `fmt.Sprintf` with type-specific functions from the `strconv` package (e.g., `strconv.FormatFloat`, `strconv.FormatBool`) to eliminate reflection and reduce memory allocations in hot paths.
