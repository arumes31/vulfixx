## 2025-02-28 - Eliminate Unsafe template.JS Cast Bypasses
**Vulnerability:** Explicit casting of `json.Marshal` output directly into `template.JS` within `html/template` contexts bypasses the template engine's context-aware escaping mechanism.
**Learning:** In Go, structs and maps rendered within `<script>` or `<script type="application/json">` blocks are inherently, natively, and safely marshaled to JSON by the `html/template` engine. There is no need for explicit JSON marshaling or explicit type bypasses.
**Prevention:** Avoid defining custom template functions that return `template.JS`, `template.HTML`, or `template.CSS` unless strictly necessary and accompanied by a dedicated scrubbing layer (like bluemonday). Rely entirely on native `{{ .Field }}` injections for JSON contexts.
## 2025-02-28 - Eliminate Unsafe template.JS Cast Bypasses
**Vulnerability:** Explicit casting of `json.Marshal` output directly into `template.JS` within `html/template` contexts bypasses the template engine's context-aware escaping mechanism.
**Learning:** In Go, structs and maps rendered within `<script>` or `<script type="application/json">` blocks are inherently, natively, and safely marshaled to JSON by the `html/template` engine. There is no need for explicit JSON marshaling or explicit type bypasses.
**Prevention:** Avoid defining custom template functions that return `template.JS`, `template.HTML`, or `template.CSS` unless strictly necessary and accompanied by a dedicated scrubbing layer (like bluemonday). Rely entirely on native `{{ .Field }}` injections for JSON contexts.
