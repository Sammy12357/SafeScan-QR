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

The visual gallery at `/__states` exists only in `MOCK_MODE`. It shows each component in both themes, including compact variants. Gallery screenshots for 375, 768, and 1440 px are in [screenshots/ui-phase-3](screenshots/ui-phase-3).

The `before/` and `existing/` folders contain matched home and admin dashboard captures from the Phase 2 base and this rebased Phase 3 branch. Both runs used the same isolated mock setup and selected views. All 12 before/after pairs have the same image dimensions. The greatest mean absolute pixel difference is 0.148/255; small differences include synthetic activity timestamps and JPEG rendering. The [Phase 0 baseline](baseline) remains available for the broader pre-polish comparison.

| Theme and width | Home | Admin dashboard |
| --- | --- | --- |
| Dark 375 | [Before](screenshots/ui-phase-3/before/dark/375/home.jpg) / [After](screenshots/ui-phase-3/existing/dark/375/home.jpg) | [Before](screenshots/ui-phase-3/before/dark/375/admin_dashboard.jpg) / [After](screenshots/ui-phase-3/existing/dark/375/admin_dashboard.jpg) |
| Dark 768 | [Before](screenshots/ui-phase-3/before/dark/768/home.jpg) / [After](screenshots/ui-phase-3/existing/dark/768/home.jpg) | [Before](screenshots/ui-phase-3/before/dark/768/admin_dashboard.jpg) / [After](screenshots/ui-phase-3/existing/dark/768/admin_dashboard.jpg) |
| Dark 1440 | [Before](screenshots/ui-phase-3/before/dark/1440/home.jpg) / [After](screenshots/ui-phase-3/existing/dark/1440/home.jpg) | [Before](screenshots/ui-phase-3/before/dark/1440/admin_dashboard.jpg) / [After](screenshots/ui-phase-3/existing/dark/1440/admin_dashboard.jpg) |
| Light 375 | [Before](screenshots/ui-phase-3/before/light/375/home.jpg) / [After](screenshots/ui-phase-3/existing/light/375/home.jpg) | [Before](screenshots/ui-phase-3/before/light/375/admin_dashboard.jpg) / [After](screenshots/ui-phase-3/existing/light/375/admin_dashboard.jpg) |
| Light 768 | [Before](screenshots/ui-phase-3/before/light/768/home.jpg) / [After](screenshots/ui-phase-3/existing/light/768/home.jpg) | [Before](screenshots/ui-phase-3/before/light/768/admin_dashboard.jpg) / [After](screenshots/ui-phase-3/existing/light/768/admin_dashboard.jpg) |
| Light 1440 | [Before](screenshots/ui-phase-3/before/light/1440/home.jpg) / [After](screenshots/ui-phase-3/existing/light/1440/home.jpg) | [Before](screenshots/ui-phase-3/before/light/1440/admin_dashboard.jpg) / [After](screenshots/ui-phase-3/existing/light/1440/admin_dashboard.jpg) |
