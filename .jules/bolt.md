## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2024-07-25 - Avoid reflection and allocation in inner loops
**Learning:** In tight loops involving string formatting and serialization (like CSV generation), `fmt.Sprintf` is incredibly slow due to reflection and dynamic string allocation. Allocating a new string slice (`row := []string{...}`) on each iteration also causes high garbage collection pressure.
**Action:** Always pre-allocate slices outside the loop and mutate them by index. Use the `strconv` package (like `strconv.FormatFloat`, `strconv.FormatBool`) instead of `fmt.Sprintf` to format primitive types in loops, as `strconv` operates without reflection.
