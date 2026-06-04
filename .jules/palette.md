## 2024-05-15 - [Add aria-hidden to decorative icons]
**Learning:** Found an accessibility issue pattern where decorative material-symbols-outlined ligature icons lack aria-hidden="true". This causes screen readers to announce the raw ligature text (e.g., "rocket launch" or "warning") out of context, creating a confusing and poor experience for users relying on assistive technologies.
**Action:** Always add aria-hidden="true" to decorative icon span elements to prevent screen readers from reading the internal ligature text. If an icon is purely informative and has no visible text alternative, ensure it has an aria-label or use visually hidden text instead.

## 2025-05-18 - [Fix screen reader double-announcement for icon buttons]
**Learning:** Found an accessibility issue where Material Symbols ligature text is double-announced by screen readers if placed directly inside an interactive element (like `<button>`) alongside an `aria-label`. The `material-symbols-outlined` class on the button itself also prevents proper focus styles from being applied to the parent.
**Action:** Always wrap ligature text inside a nested `<span class="material-symbols-outlined" aria-hidden="true">` element inside buttons, rather than applying the class directly to the button. This prevents screen reader double-announcement and ensures the button can have its standard focus ring and styling.
