## 2026-07-18 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-18 - Pre-compute repeated string transformations to reduce allocations
**Learning:** Calling `strings.ToLower()` inside a loop where one of the operands is constant results in unnecessary allocations on every iteration. Also, repeatedly calling tokenization functions like `strings.Fields()` on the same string in sequential passes is inefficient.
**Action:** When evaluating strings in multiple heuristics, tokenize the string once and reuse the resulting slice. For static match terms inside loops, pre-compute the transformed (e.g. lowercased) versions into a cached structure at `init()` time.
