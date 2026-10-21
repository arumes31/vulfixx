## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-10-19 - Use struct as map key for deduplication to eliminate fmt.Sprintf overhead
**Learning:** When deduplicating compound data in Go (e.g., using a map to track seen items), using a struct with comparable fields as the map key is far more efficient than constructing string keys via `fmt.Sprintf` or concatenation. This eliminates reflection and heap allocation overhead in tight loops.
**Action:** Always prefer using a small, comparable struct as a map key instead of allocating new strings via `fmt.Sprintf` for tracking uniqueness.
