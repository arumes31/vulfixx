## 2025-02-28 - Material Symbols Accessibility
**Learning:** Screen readers often attempt to announce the raw text inside ligature-based icons (e.g., `<span class="material-symbols-outlined">filter_alt_off</span>` being read as "filter alt off"), which creates a confusing and unpolished experience, especially for icon-only buttons.
**Action:** Always add `aria-hidden="true"` to the `span` element containing the ligature text, and ensure the parent interactive element (button/link) has a descriptive `aria-label`.
