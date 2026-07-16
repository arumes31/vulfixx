## 2026-07-16 - 🛡️ Sentinel: [CRITICAL/HIGH] Fix XSS vulnerability
**Vulnerability:** Explicit rendering of JSON inside application/json scripts using `template.JS`.
**Learning:** In Go's `html/template` package, structs and maps rendered within `<script>` or `<script type="application/json">` blocks are natively and safely marshaled to JSON. Explicitly casting `json.Marshal` results to `template.JS` bypasses context-aware escaping, potentially introducing XSS.
**Prevention:** Do not explicitly cast raw strings or JSON out of `json.Marshal` into `template.JS` or `template.HTML` in output views. Rely on the built-in context-aware engine and if strictly necessary, sanitize input strings first before casting.
