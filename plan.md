1. **Remove the `marshal` template function in `internal/web/template_funcs.go`.**
   - The `marshal` function calls `json.Marshal` and casts the result to `template.JS`. Because `template.JS` is considered already-escaped JavaScript, this bypasses the `html/template` package's automatic context-aware escaping.
   - It is safer to simply pass the Go values (e.g., `map[string]interface{}`, structs, slices) directly to the template and let `html/template` automatically marshal them and properly escape them for a `<script>` context.

2. **Update templates to remove `{{marshal ...}}` and use `{{...}}` instead.**
   - In `templates/dashboard.html`
   - In `templates/public_dashboard.html`
   - In `templates/cve_detail.html`

3. **Update JSON-LD generation in `internal/web/dashboard_handlers.go`.**
   - Currently, `jsonLD` is manually marshaled, escaped with `strings.ReplaceAll(..., "</", "<\/")`, and then wrapped in `template.JS`.
   - Instead, pass the raw `jsonLD` map directly to the template as `"JSONLD": jsonLD` and remove the manual marshaling, string replacement, and `template.JS` conversion.
   - The `html/template` package will automatically marshal the map into valid, safely escaped JSON within the `<script type="application/ld+json">` tag.

4. **Update the test for `template_funcs.go`.**
   - Remove the `"marshal"` test case from `internal/web/template_funcs_test.go` since the function is being removed.

5. **Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.**
   - Call `pre_commit_instructions` and follow its instructions to verify tests pass and code is formatted.

6. **Submit PR.**
   - Submit the PR with prefix `🛡️ Sentinel:` and explain the XSS mitigation in the description.
