## 2025-02-12 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2025-02-12 - Pre-allocate slices and avoid fmt.Sprintf in tight loops
**Learning:** Using `fmt.Sprintf` and dynamically allocating slices inside high-frequency loops (like CSV row generation for thousands of CVEs) causes significant allocation overhead and slows down processing by ~50%.
**Action:** Pre-allocate slice arrays outside of loops and re-use indexes (`row[i] = x`). Substitute reflection-based formatting like `fmt.Sprintf` with explicit `strconv` formatters (e.g., `strconv.FormatFloat`, `strconv.FormatBool`) to eliminate runtime overhead in tight loops.
