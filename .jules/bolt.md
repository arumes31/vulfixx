## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-22 - Optimize data export loops by pre-allocating slices
**Learning:** Inside data export loops (like generating CSVs), allocating a new string slice and using reflection-heavy `fmt.Sprintf` on every iteration introduces significant memory allocations and CPU overhead.
**Action:** Pre-allocate the string slice outside the loop using `make([]string, size)` and reuse it via index assignment. Replace `fmt.Sprintf` with explicit `strconv` formatting (e.g. `strconv.FormatFloat`, `strconv.FormatBool`) and use time formatting constants (like `time.DateOnly`) to avoid allocation overhead.
