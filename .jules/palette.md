## 2024-05-15 - [Add aria-hidden to decorative icons]
**Learning:** Found an accessibility issue pattern where decorative material-symbols-outlined ligature icons lack aria-hidden="true". This causes screen readers to announce the raw ligature text (e.g., "rocket launch" or "warning") out of context, creating a confusing and poor experience for users relying on assistive technologies.
**Action:** Always add aria-hidden="true" to decorative icon span elements to prevent screen readers from reading the internal ligature text. If an icon is purely informative and has no visible text alternative, ensure it has an aria-label or use visually hidden text instead.

## 2026-05-19 - Adding aria-hidden to decorative icons
**Learning:** It's important to add `aria-hidden="true"` to `material-symbols-outlined` span tags, especially in table headers, buttons, and links. If missing, screen readers may read the raw ligature strings like "arrow_upward", "filter_alt_off", or "login", leading to a confusing user experience. Additionally, icon-only interactive elements must have `aria-label` attributes.
**Action:** When adding or modifying material icons, always verify if they are purely decorative and add `aria-hidden="true"` if they are. For icon-only buttons, ensure they have a descriptive `aria-label`.

## 2026-05-25 - Safe Inline Event Handlers
**Learning:** When using inline JavaScript event handlers in Go templates (like `onclick="document.getElementById('target').click()"` for an empty state CTA button), standard property access can cause `TypeError`s if the target element doesn't exist or is removed later.
**Action:** Always use optional chaining (e.g., `document.getElementById('target')?.click()`) for safer, defensive event handler implementations in raw templates.

## 2026-05-28 - ARIA attributes for alert/status containers
**Learning:** Flash messages indicating success or error states need proper ARIA roles to ensure they are immediately announced by screen readers without requiring the user to navigate to them.
**Action:** Use `role="alert" aria-atomic="true"` for error messages and `role="status" aria-live="polite"` for non-critical information/success messages in template partials.

## 2026-06-07 - Form Input Label Association
**Learning:** Without explicit `id` attributes on form inputs that match the `for` attribute on corresponding `<label>` elements, screen readers fail to associate the label with the input. Furthermore, using identical IDs in both the primary view and dynamically generated modals causes ID collisions and breaks label resolution.
**Action:** Always assign a unique `id` to every `<input>` and `<select>` and explicitly link them to `<label for="[id]">`. For dynamic forms inside modals, use a prefix like `edit_` to ensure IDs remain globally unique on the page.
## 2026-06-20 - [Accessible mobile navigation]
**Learning:** Abbreviated mobile navigation text (e.g. 'Dash', 'Subs', 'Set', 'Exit') alongside icons can be confusing or inaccessible for screen reader users without full descriptive context.
**Action:** Always add explicit, full-word `aria-label` attributes to mobile navigation links or buttons that rely on heavily abbreviated text for layout constraints.
## 2026-10-25 - Keyboard accessible table rows
**Learning:** Found an accessibility issue where interactive table rows (used for navigation) lacked keyboard accessibility (tabindex="0" and aria-label) and did not support keyboard interaction (Enter or Space key). This prevents users relying on keyboard navigation from interacting with clickable table rows.
**Action:** Always ensure interactive rows have `tabindex="0"`, a descriptive `aria-label`, visible focus states (`focus:bg-white/[0.05] focus:outline-none`), and JavaScript event listeners for both `click` and `keydown` events (handling `Enter` and `Space` keys).
## 2026-10-25 - Avoid mingling backend updates with frontend work
**Learning:** Found that grouping a backend dependency vulnerability fix (go-chi update) into an accessibility pull request can cause code review rejections due to scope creep and violating persona constraints. However, fixing broken CI is also a priority.
**Action:** When a backend dependency causes CI to fail during a frontend task, split the resolution into two distinct commits or separate branches if necessary to preserve clean separation of concerns and maintain pull request scope.
