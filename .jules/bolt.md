## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-10-25 - Avoid fmt.Sprintf for compound map keys in tight loops
**Learning:** Using `fmt.Sprintf` to create string keys for compound data in a map creates reflection and heap allocation overhead, especially in tight loops like mass data deduplication.
**Action:** Use a struct with comparable fields as the map key instead to eliminate the string allocation overhead and drastically reduce execution time (e.g. from 5s down to 1.8s for 10M keys).
