## 2024-05-30 - Fix unsafe template.JS bypass in dashboard templates
**Vulnerability:** A custom `marshal` template function bypassed context-aware JSON encoding using `template.JS`, creating a potential XSS vulnerability.
**Learning:** `html/template` provides secure, context-aware JSON escaping by default inside `<script type="application/json">` tags, meaning manual escaping bypasses using `template.JS` are anti-patterns and unsafe.
**Prevention:** Avoid force casting input to `template.HTML`, `template.JS`, or `template.CSS` without verifying the input is rigorously sanitized. Always rely on native `html/template` behavior where possible.
