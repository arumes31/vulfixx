## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## $(date +%Y-%m-%d) - Eliminate fmt.Sprintf inside tight loops for map deduplication tracking
**Learning:** `fmt.Sprintf` uses reflection and allocates memory on the heap, which causes measurable CPU and memory overhead when used inside tight loops to dynamically generate composite strings (e.g., combining strings to create unique map keys).
**Action:** When tracking uniqueness or deduplicating elements in Go loops (e.g., using a map), define a comparable struct with the specific target fields and use instances of that struct directly as the map key, avoiding string concatenation entirely.
