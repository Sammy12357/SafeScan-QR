# Shared UI states

`templates/_states.html` provides Jinja macros for server-rendered empty, loading, error, and notice states. `static/ui-states.js` provides the matching browser API as `UIStates`. Both use `static/styles-states.css` and the SVG symbols in `static/icons/states.svg`.

## Browser API

```js
UIStates.empty(container, {
  kind: 'first-use', // or no-results, no-access
  title: 'No scans yet',
  body: 'Scan a QR code and it will appear here.',
  actionLabel: 'Scan a QR code',
  actionHref: '/#scanner',
  compact: false
});

const progress = UIStates.loading(container, {
  label: 'Loading scan history',
  skeletonRows: 3,
  retry: loadHistory
});
// On completion, call progress.finish(), then render content or an empty state.
// UIStates.empty/error/notice also cancel an active loading state automatically.

UIStates.error(container, {
  title: 'Scan history didn\'t load',
  body: 'Check your connection and try again.',
  retry: loadHistory,
  ref: requestId,
  focus: true
});

await UIStates.busy(saveButton, saveChanges, { label: 'Saving…' });
const data = await UIStates.fetchJson('/api/history');
```

Dynamic strings are inserted as text. Loading indicators appear after 300 ms and become a retryable error after 15 seconds. A loading controller must be finished when a request succeeds. `UIStates.busy` restores the button and prevents duplicate actions while its promise is pending. `UIStates.fetchJson` keeps the API's `error` string and exposes optional `code`, `hint`, `requestId`, `retryAfter`, and `status` on thrown errors.

The visual gallery at `/__states` exists only in `MOCK_MODE`. It shows each component in both themes, including compact variants. Screenshots for 375, 768, and 1440 px are in [screenshots/ui-phase-3](screenshots/ui-phase-3). The `existing/` subfolder records the home and admin views after this phase for comparison with the [Phase 0 baseline](baseline). Eight representative views were compared locally at all six layout/theme combinations: 30 of 48 screenshots were pixel-identical, and the greatest mean absolute pixel difference was 0.212/255. The small differences occur on views with dynamic content.
