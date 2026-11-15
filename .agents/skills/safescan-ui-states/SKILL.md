---
name: safescan-ui-states
description: Use when changing SafeScan pages, templates, CSS, or frontend JS, especially loading, empty, error, spacing, and accessibility behavior.
---

# SafeScan UI states

Read `docs/plans/ui-polish.md` and the relevant current component before editing. Preserve the established SafeScan visual language unless the user asks to change it.

- Use the shared `--space-*` tokens or existing semantic spacing aliases for spacing in templates and CSS. Keep style rules in static stylesheets.
- A view that loads data should make loading, empty, error, and content outcomes understandable. Show a retry action when one can work; do not present an incomplete scan as safe.
- Request buttons should show progress and prevent duplicate submission. Error text should say what happened and what the person can do next, without exposing provider details or stack traces.
- Keep browser error pages useful while API responses preserve a plain-string `error` field for mobile clients.
- Check keyboard navigation, focus, screen-reader announcements, reduced motion, mobile layout, and both themes for affected UI.
- Capture visual evidence at the breakpoints relevant to the change. Do not require a full screenshot matrix for a small, unrelated edit.
