## 2026-10-28 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-10-28 - Optimize cache lookups before expensive validation
**Learning:** Performing expensive operations like AST construction (`syntax.Parse`) or complex validation prior to checking a cache layer defeats the purpose of caching. The CPU overhead is still incurred on every cache hit.
**Action:** Always perform cache lookups (like `sync.Map.Load()`) before executing any expensive string parsing, validation, or AST construction to maximize cache performance.
## 2026-11-10 - Split Cache Maps for Zero-Allocation Lookups
**Learning:** Using a single `sync.Map` for both raw keywords and compiled regex patterns with string concatenation to form the key introduces memory allocation overhead and risks key collisions.
**Action:** Always use dedicated `sync.Map` caches for different data types or contexts, and use raw unmodified inputs as cache keys whenever possible to enable zero-allocation lookups.
