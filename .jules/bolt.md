## 2026-10-28 - Reorder cache checks in expensive functions
**Learning:** In functions that perform expensive operations (like parsing or syntax validation) before doing a cache lookup (like in `getPatternRegex`), the cache's purpose is partially defeated. The expensive operations are executed on every call, even for cached inputs, wasting CPU cycles.
**Action:** Always perform cache lookups at the very beginning of a function, before executing any expensive operations, unless those operations are strictly necessary to generate the cache key.
