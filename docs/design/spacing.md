# Spacing

SafeScan uses a shared spacing scale in `static/styles-base.css`. The scale is
based on 4px increments, with a 2px detail step for small icon and text gaps.
The values and names are shared by dark and light themes.

| Token | Value | Use |
| --- | ---: | --- |
| `--space-0` | `0px` | No space or flush edges; a length so it works in negative `calc()` offsets |
| `--space-1` | `2px` | Fine alignment inside small controls |
| `--space-2` | `4px` | Tight icon and text gaps |
| `--space-3` | `8px` | Inline gaps and compact rows |
| `--space-4` | `12px` | Form field gaps and vertical control padding |
| `--space-5` | `16px` | Default stacked gap and mobile card padding |
| `--space-6` | `20px` | Medium internal gap |
| `--space-7` | `24px` | Desktop card padding and card gaps |
| `--space-8` | `32px` | Spacing within a page section |
| `--space-9` | `40px` | Larger section separation |
| `--space-10` | `48px` | Default separation between page sections |
| `--space-11` | `64px` | Hero and empty state breathing room |
| `--space-12` | `96px` | Top of page hero spacing only |

Use a semantic alias when the relationship is clear:

| Alias | Meaning |
| --- | --- |
| `--gap-inline` | Items sharing a row (`8px`) |
| `--gap-stack` | Blocks stacked in a component (`16px`) |
| `--gap-section` | Distinct page sections (`48px`) |
| `--pad-control-y` / `--pad-control-x` | Control padding (`12px` / `16px`) |
| `--pad-card` | Card padding (`24px`) |
| `--pad-page` | Fluid page padding, clamped from `16px` to `32px` |

Prefer `gap` on a flex or grid parent to margins between siblings. For an
unusual layout, use the nearest numbered token and note why a semantic alias
does not fit. Admin pages use the same numbered scale and may set tighter
aliases within their own scope.

Phase 2 migrated `padding`, `margin`, `gap`, `row-gap`, `column-gap`, and `inset`
in the site and admin styles. Page-specific styles now live in static stylesheets.
The spacing test enforces tokens in these properties, with a documented exception
for the scanner's viewport-based full-bleed offset. Borders, outlines, font sizes,
and fixed component dimensions are outside the spacing rule. The [visual review](spacing-review/README.md)
compares phone, tablet, and desktop screenshots in both themes.
