## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.
## $(date +%Y-%m-%d) - Cache AES-GCM cipher objects
**Learning:** In Go's `crypto/cipher` package, AES-GCM `cipher.AEAD` implementations (such as those returned by `cipher.NewGCM`) are safe for concurrent use and maintain no internal encryption state between calls. They can be safely cached and reused across multiple goroutines to optimize performance, avoiding repeated key derivations and cipher block allocations.
**Action:** When performing repeated encryptions/decryptions with the same key, cache the resulting `cipher.AEAD` instance instead of recreating it on every call.
