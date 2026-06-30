## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-06-30 - Memoize struct fields in notification loops
**Learning:** In worker loops that process one-to-many relationship notifications (like one CVE matched against many user subscriptions), performing dynamic fetch operations (like `cve.OSINTData = fetchOSINTLinks()` ) inside the per-user inner loop triggers redundant logic and multiple redis/cache reads. By moving or memoizing the fetch on the shared parent object (e.g. `if cve.OSINTData == nil { ... }`), the external operations happen only once per parent object.
**Action:** When evaluating notification dispatch loops, memoize dynamically fetched data on the shared parent struct if the fetched data is independent of the notification recipient.
