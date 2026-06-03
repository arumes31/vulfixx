## 2024-05-15 - [Add aria-hidden to decorative icons]
**Learning:** Found an accessibility issue pattern where decorative material-symbols-outlined ligature icons lack aria-hidden="true". This causes screen readers to announce the raw ligature text (e.g., "rocket launch" or "warning") out of context, creating a confusing and poor experience for users relying on assistive technologies.
**Action:** Always add aria-hidden="true" to decorative icon span elements to prevent screen readers from reading the internal ligature text. If an icon is purely informative and has no visible text alternative, ensure it has an aria-label or use visually hidden text instead.

## 2025-02-12 - [Button Icons A11y and Screen Readers]
**Learning:** Placing Material Symbols ligature text directly inside `<button>` tags without an `aria-hidden` span wrapper causes screen readers to read the raw ligature text (like "description" or "contrast") alongside the `aria-label`, creating confusing double-announcements on interactive elements.
**Action:** Always wrap ligature text inside `<button>` tags with a nested `<span class="material-symbols-outlined" aria-hidden="true">`. Keep the button's `aria-label` but ensure the internal ligature text itself is hidden from screen readers.
