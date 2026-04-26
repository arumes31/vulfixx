## 2026-04-26 - Icon-only buttons Accessibility
**Learning:** Found several Material Design icon buttons across the application templates that used the `title` attribute for tooltips but missed `aria-label` attributes for screen readers.
**Action:** Always ensure any `<button>` whose content is exclusively an icon ligature (e.g. `<span class="material-symbols-outlined">delete</span>`) includes a descriptive `aria-label` to provide context for visually impaired users.
