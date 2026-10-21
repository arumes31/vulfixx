## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2024-10-21 - Optimize map keys for deduplication
**Learning:** Using a struct with comparable fields as a map key eliminates string formatting (`fmt.Sprintf`) and memory allocation overhead in deduplication logic compared to building composite string keys.
**Action:** When tracking unique compound items (like Vendor, Product, Version) in a map, use a custom struct instead of constructing string keys via `fmt.Sprintf` or concatenation.
