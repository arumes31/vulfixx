## 2026-07-02 - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-02 - Memoize external fetch in notification loop
**Learning:** In notification dispatch loops involving one-to-many relationships (like sending CVE alerts to multiple users), performing redundant external fetches (like OSINT data) inside the per-recipient loop introduces severe performance bottlenecks.
**Action:** When fetched data is independent of the recipient, always memoize it on the shared parent object (e.g., `if cve.OSINTData == nil { cve.OSINTData = fetch() }`) to eliminate duplicate API/cache calls across the loop iterations.
