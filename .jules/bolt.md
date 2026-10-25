## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-10-25 - Optimize string processing in hot paths
**Learning:** `fmt.Sprintf` incurs significant reflection and allocation overhead, especially when used in tight loops (like deduplicating FortiGuard products via map keys) or heavily accessed functions (like generating dashboard cache keys).
**Action:** Replace `fmt.Sprintf` with `strconv` for numeric formatting, string concatenation, or struct-based map keys to drastically reduce allocations and improve performance in hot paths without sacrificing correctness.
