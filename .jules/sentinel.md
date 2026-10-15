## 2025-05-18 - Enforce native `html/template` escaping for JSON in script tags
**Vulnerability:** XSS vulnerability through unsafe casting of user-supplied data into `template.JS(...)` for usage within `<script>` blocks.
**Learning:** `html/template` provides context-aware escaping. When variables are embedded inside `<script>` or `<script type="application/json">` blocks, complex types (like maps/structs) and primitives are automatically JSON-encoded, with dangerous characters (`<`, `>`) safely escaped into unicode equivalents by its internal `jsValEscaper`.
**Prevention:** Do not manually use `json.Marshal` combined with forceful `template.JS(...)` casting. Always pass the native Go struct or map directly to the `html/template` variable (`{{.Variable}}`) to leverage its secure, built-in escaping.

## 2026-06-29 - Fixed X-Forwarded-For IP Spoofing
**Vulnerability:** The application was vulnerable to IP spoofing because it trusted the first (leftmost) IP in the `X-Forwarded-For` header.
**Learning:** The leftmost IP is provided by the client and can easily be spoofed. The correct approach is to parse from right to left, stopping at the first untrusted proxy.
**Prevention:** Always iterate `X-Forwarded-For` from right to left and only trust IP addresses provided by known, trusted proxies.

## 2026-07-28 - Audit of XSS vulnerabilities in WebGUI
**Vulnerability:** Unsafe flat rendering using `text/template` utility instead of `html/template` can lead to explicit text rendering. Forceful cast of user-supplied string parameters into `template.HTML(...)`, `template.JS(...)`, or `template.CSS(...)` can lead to XSS.
**Learning:** Use `html/template` which prevents context escaping issues and provides context-aware escaping. Ensure any usage of `template.HTML(...)`, such as in rich email templates, goes through an approved HTML scrubbing library like `bluemonday` immediately before casting to ensure it's sanitized.
**Prevention:** Replace any `text/template` usage with `html/template`. Ban the use of `template.HTML`, `template.JS`, `template.CSS` without strict inputs sanitation immediately prior to it.
