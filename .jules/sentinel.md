## 2025-05-18 - Enforce native `html/template` escaping for JSON in script tags
**Vulnerability:** XSS vulnerability through unsafe casting of user-supplied data into `template.JS(...)` for usage within `<script>` blocks.
**Learning:** `html/template` provides context-aware escaping. When variables are embedded inside `<script>` or `<script type="application/json">` blocks, complex types (like maps/structs) and primitives are automatically JSON-encoded, with dangerous characters (`<`, `>`) safely escaped into unicode equivalents by its internal `jsValEscaper`.
**Prevention:** Do not manually use `json.Marshal` combined with forceful `template.JS(...)` casting. Always pass the native Go struct or map directly to the `html/template` variable (`{{.Variable}}`) to leverage its secure, built-in escaping.

## 2026-06-29 - Fixed X-Forwarded-For IP Spoofing
**Vulnerability:** The application was vulnerable to IP spoofing because it trusted the first (leftmost) IP in the `X-Forwarded-For` header.
**Learning:** The leftmost IP is provided by the client and can easily be spoofed. The correct approach is to parse from right to left, stopping at the first untrusted proxy.
**Prevention:** Always iterate `X-Forwarded-For` from right to left and only trust IP addresses provided by known, trusted proxies.

## 2026-11-02 - [Remove manual JSON encoding for template rendering]
**Vulnerability:** XSS risk from manual JSON marshaling and string replacement in templates
**Learning:** Go's html/template package is context-aware. If you pass a native struct/map to a template inside a `<script>` tag, it automatically applies secure, context-appropriate JSON encoding (handling `</script>` naturally). Manually marshaling to string bypasses this protection, leading to invalid JSON-LD output or XSS vulnerabilities if cast directly.
**Prevention:** Always pass native Go structs/maps directly into Go templates for script blocks, rather than manually calling `json.Marshal` and doing string replacements.
