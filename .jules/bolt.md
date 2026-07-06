## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## 2026-07-06 - Cache cryptographic keys derived via HKDF
**Learning:** Deriving symmetric keys per-request using HKDF (like in getCipher for webhooks) introduces substantial CPU overhead and increases latency, as HKDF execution is computationally expensive compared to standard GCM operations.
**Action:** When deriving keys that only change on environment restarts or configuration updates, cache the derived cipher object (e.g., cipher.AEAD) behind a sync.RWMutex based on the raw input key.
