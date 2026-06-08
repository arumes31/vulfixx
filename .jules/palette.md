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
## 2025-06-08 - Added descriptive aria labels
**Learning:** Some elements like buttons or links used for severity badges or pagination only had icons, and screen readers lack the context on their purpose without `aria-label`s.
**Action:** Always add descriptive `aria-label`s to purely visual indicators and buttons using icons to give screen readers proper context.
