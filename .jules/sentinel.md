## 2024-05-18 - Fix Wildcard SQL Injection in Dashboard Handlers
**Vulnerability:** SQL Injection in Dashboard Handlers via Keyword Filtering (`c.description ILIKE '%%' || us.keyword || '%%'`)
**Learning:** Using untrusted keyword input directly in `ILIKE` pattern construction allows wildcard injection (`%`, `_`), which can bypass intended logic and degrade database performance or lead to data leakage if carefully crafted.
**Prevention:** Always use proper escaping like `REPLACE` with `ESCAPE '\'` for user-provided parts of `ILIKE` clauses, avoiding direct string concatenation, as demonstrated in `export.go`.
