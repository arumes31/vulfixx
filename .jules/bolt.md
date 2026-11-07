## 2026-10-28 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-10-28 - Optimize cache lookups before expensive validation
**Learning:** Performing expensive operations like AST construction (`syntax.Parse`) or complex validation prior to checking a cache layer defeats the purpose of caching. The CPU overhead is still incurred on every cache hit.
**Action:** Always perform cache lookups (like `sync.Map.Load()`) before executing any expensive string parsing, validation, or AST construction to maximize cache performance.
## 2026-11-07 - Optimize cache lookups by avoiding key transformations on hits
**Learning:** Constructing keys for cache lookups (like `regexp.QuoteMeta` and string concatenation) introduces allocation overhead and CPU cycles even on cache hits. Using a dedicated cache map allows raw inputs to be used as cache keys, leading to zero-allocation lookups.
**Action:** When implementing caching layers, avoid sharing a single cache map for different data types to prevent key collisions. Use dedicated cache maps to ensure data integrity and enable zero-allocation lookups using raw input keys.
