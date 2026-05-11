## 2025-05-11 - Screen readers read Material Symbols ligatures
**Learning:** Screen readers will pronounce the raw ligature text (e.g. 'filter_alt_off') of Material Symbols inside interactive elements if they are not explicitly hidden from assistive technologies. This is confusing for users.
**Action:** Always add `aria-hidden="true"` to the `<span class="material-symbols-outlined">` element. If it is an icon-only button, add an `aria-label` to the parent `<button>` element to provide the actual context.
