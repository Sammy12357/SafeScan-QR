# Phase 5 form and message review

The **before** captures use merged Phase 4 `main` at commit `95868bf`. The **after** captures use the rebased Phase 5 worktree. Both were made with an isolated local mock server, throwaway SQLite database, and synthetic accounts. The same submitted values were used for each error-state pair. The Phase 4 API-key response generated a synthetic key; its screenshot masks that key.

`normal/` contains login, profile, data request, Alpha payment, and waitlist pages at 375, 768, and 1440 CSS pixels in dark and light themes. These 30 captures use the Phase 0 `scripts/ui_screenshots.py` harness.

`error/` contains public form validation states and `admin-error/` contains owner-only form validation states at all three widths in both themes. The 42 after captures and 42 matching before captures are linked below. The browser's native form validation was bypassed so the actual server responses could be reviewed. In production, local email/password sign-in is disabled; register captures use the mock-mode form.

These images show layout, retained non-secret input, and visible errors. They do not replace a keyboard and VoiceOver pass on a physical device.

## Error-state before/after matrix

| View | Width | Theme | Before: merged Phase 4 | After: Phase 5 |
| --- | ---: | --- | --- | --- |
| Data request | 375 | dark | [Before](before/error/dark/375/data_request.jpg) | [After](error/dark/375/data_request.jpg) |
| Data request | 375 | light | [Before](before/error/light/375/data_request.jpg) | [After](error/light/375/data_request.jpg) |
| Data request | 768 | dark | [Before](before/error/dark/768/data_request.jpg) | [After](error/dark/768/data_request.jpg) |
| Data request | 768 | light | [Before](before/error/light/768/data_request.jpg) | [After](error/light/768/data_request.jpg) |
| Data request | 1440 | dark | [Before](before/error/dark/1440/data_request.jpg) | [After](error/dark/1440/data_request.jpg) |
| Data request | 1440 | light | [Before](before/error/light/1440/data_request.jpg) | [After](error/light/1440/data_request.jpg) |
| Profile username | 375 | dark | [Before](before/error/dark/375/profile.jpg) | [After](error/dark/375/profile.jpg) |
| Profile username | 375 | light | [Before](before/error/light/375/profile.jpg) | [After](error/light/375/profile.jpg) |
| Profile username | 768 | dark | [Before](before/error/dark/768/profile.jpg) | [After](error/dark/768/profile.jpg) |
| Profile username | 768 | light | [Before](before/error/light/768/profile.jpg) | [After](error/light/768/profile.jpg) |
| Profile username | 1440 | dark | [Before](before/error/dark/1440/profile.jpg) | [After](error/dark/1440/profile.jpg) |
| Profile username | 1440 | light | [Before](before/error/light/1440/profile.jpg) | [After](error/light/1440/profile.jpg) |
| Register | 375 | dark | [Before](before/error/dark/375/register.jpg) | [After](error/dark/375/register.jpg) |
| Register | 375 | light | [Before](before/error/light/375/register.jpg) | [After](error/light/375/register.jpg) |
| Register | 768 | dark | [Before](before/error/dark/768/register.jpg) | [After](error/dark/768/register.jpg) |
| Register | 768 | light | [Before](before/error/light/768/register.jpg) | [After](error/light/768/register.jpg) |
| Register | 1440 | dark | [Before](before/error/dark/1440/register.jpg) | [After](error/dark/1440/register.jpg) |
| Register | 1440 | light | [Before](before/error/light/1440/register.jpg) | [After](error/light/1440/register.jpg) |
| Waitlist | 375 | dark | [Before](before/error/dark/375/waitlist.jpg) | [After](error/dark/375/waitlist.jpg) |
| Waitlist | 375 | light | [Before](before/error/light/375/waitlist.jpg) | [After](error/light/375/waitlist.jpg) |
| Waitlist | 768 | dark | [Before](before/error/dark/768/waitlist.jpg) | [After](error/dark/768/waitlist.jpg) |
| Waitlist | 768 | light | [Before](before/error/light/768/waitlist.jpg) | [After](error/light/768/waitlist.jpg) |
| Waitlist | 1440 | dark | [Before](before/error/dark/1440/waitlist.jpg) | [After](error/dark/1440/waitlist.jpg) |
| Waitlist | 1440 | light | [Before](before/error/light/1440/waitlist.jpg) | [After](error/light/1440/waitlist.jpg) |
| Admin API key | 375 | dark | [Before](before/admin-error/dark/375/api_key.jpg) | [After](admin-error/dark/375/api_key.jpg) |
| Admin API key | 375 | light | [Before](before/admin-error/light/375/api_key.jpg) | [After](admin-error/light/375/api_key.jpg) |
| Admin API key | 768 | dark | [Before](before/admin-error/dark/768/api_key.jpg) | [After](admin-error/dark/768/api_key.jpg) |
| Admin API key | 768 | light | [Before](before/admin-error/light/768/api_key.jpg) | [After](admin-error/light/768/api_key.jpg) |
| Admin API key | 1440 | dark | [Before](before/admin-error/dark/1440/api_key.jpg) | [After](admin-error/dark/1440/api_key.jpg) |
| Admin API key | 1440 | light | [Before](before/admin-error/light/1440/api_key.jpg) | [After](admin-error/light/1440/api_key.jpg) |
| Admin breach report | 375 | dark | [Before](before/admin-error/dark/375/breach.jpg) | [After](admin-error/dark/375/breach.jpg) |
| Admin breach report | 375 | light | [Before](before/admin-error/light/375/breach.jpg) | [After](admin-error/light/375/breach.jpg) |
| Admin breach report | 768 | dark | [Before](before/admin-error/dark/768/breach.jpg) | [After](admin-error/dark/768/breach.jpg) |
| Admin breach report | 768 | light | [Before](before/admin-error/light/768/breach.jpg) | [After](admin-error/light/768/breach.jpg) |
| Admin breach report | 1440 | dark | [Before](before/admin-error/dark/1440/breach.jpg) | [After](admin-error/dark/1440/breach.jpg) |
| Admin breach report | 1440 | light | [Before](before/admin-error/light/1440/breach.jpg) | [After](admin-error/light/1440/breach.jpg) |
| Admin user deletion | 375 | dark | [Before](before/admin-error/dark/375/user_delete.jpg) | [After](admin-error/dark/375/user_delete.jpg) |
| Admin user deletion | 375 | light | [Before](before/admin-error/light/375/user_delete.jpg) | [After](admin-error/light/375/user_delete.jpg) |
| Admin user deletion | 768 | dark | [Before](before/admin-error/dark/768/user_delete.jpg) | [After](admin-error/dark/768/user_delete.jpg) |
| Admin user deletion | 768 | light | [Before](before/admin-error/light/768/user_delete.jpg) | [After](admin-error/light/768/user_delete.jpg) |
| Admin user deletion | 1440 | dark | [Before](before/admin-error/dark/1440/user_delete.jpg) | [After](admin-error/dark/1440/user_delete.jpg) |
| Admin user deletion | 1440 | light | [Before](before/admin-error/light/1440/user_delete.jpg) | [After](admin-error/light/1440/user_delete.jpg) |
