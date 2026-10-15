## 2024-06-28 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-10-15 - Avoid struct-to-string conversion for map keys in hot loops
**Learning:** Constructing strings using `fmt.Sprintf` or string concatenation to serve as unique map keys in tight loops (like deduplicating slices of structs) involves unnecessary reflection, heap allocations, and garbage collection overhead. Since structs with comparable fields can be used directly as map keys in Go, using them avoids this overhead.
**Action:** When deduplicating or tracking structs in a map, use a minimal struct with comparable fields as the map key instead of converting the struct fields to a string key.
