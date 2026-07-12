## 2024-05-23 - Prevent XSS in HTML Templates
**Vulnerability:** XSS via explicit casting of user data to `template.JS` bypassing `html/template` context-aware escaping.
**Learning:** `html/template` safely natively marshals JSON to variables within `<script type="application/json">` blocks; manually casting using `template.JS` disables these protections and can lead to code execution.
**Prevention:** Remove explicit casts to `template.JS` (like `marshal` template func) and let `html/template` handle struct/map values natively in `<script>` tags.
