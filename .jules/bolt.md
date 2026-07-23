## $(date +%Y-%m-%d) - Preload active team name into session to avoid per-render DB query
**Learning:** For rendering templates, fallback queries executed on every page load can introduce unnecessary overhead. Storing slightly more data in the session cookie (like a small team name string) can completely eliminate these per-render fallback database queries.
**Action:** When evaluating database queries in shared layout or rendering functions, check if the data can be preloaded into the session during state transitions (like login or team switching) instead of querying it dynamically on every request.
## 2024-06-27 - Pre-compile regular expressions
**Learning:** Compiling regex in tight loops or frequently called functions is a performance anti-pattern. Pre-compiling them at the package level saves CPU overhead.
**Action:** Always declare regular expressions as package-level variables with `regexp.MustCompile` instead of inside loops.

## 2026-07-23 - CSV Export Allocation Bottleneck
**Learning:** In Go loops that iterate potentially thousands of times (like generating CSV rows from database records), allocating a new  slice and using reflection-heavy functions like  on every iteration causes significant garbage collection overhead and slower execution times. Using  evaluates the slice synchronously, meaning it is safe to reuse a single pre-allocated slice.
**Action:** Always pre-allocate the slice outside the loop () and mutate elements by index. Prefer strongly typed  functions (e.g., , ) over  for primitive types to avoid reflection and allocation.

## 2026-07-23 - CSV Export Allocation Bottleneck
**Learning:** In Go loops that iterate potentially thousands of times (like generating CSV rows from database records), allocating a new `[]string` slice and using reflection-heavy functions like `fmt.Sprintf` on every iteration causes significant garbage collection overhead and slower execution times. Using `csv.Writer.Write` evaluates the slice synchronously, meaning it is safe to reuse a single pre-allocated slice.
**Action:** Always pre-allocate the slice outside the loop (`row := make([]string, size)`) and mutate elements by index. Prefer strongly typed `strconv` functions (e.g., `strconv.FormatFloat`, `strconv.FormatBool`) over `fmt.Sprintf` for primitive types to avoid reflection and allocation.
