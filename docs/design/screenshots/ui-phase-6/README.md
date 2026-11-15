# Phase 6 loading review

The Phase 0 mock-mode screenshot harness captured the six affected views at 375, 768, and 1440 CSS pixels in dark and light mode. These after images use the Phase 6 branch. The baseline links are the Phase 0 screenshots. Dynamic timestamps and mock content can differ.

| View | Dark 375 | Dark 768 | Dark 1440 | Light 375 | Light 768 | Light 1440 |
|---|---|---|---|---|---|---|
| Home scanner | [before](../../baseline/dark/375/home.jpg) / [after](after/dark/375/home.jpg) | [before](../../baseline/dark/768/home.jpg) / [after](after/dark/768/home.jpg) | [before](../../baseline/dark/1440/home.jpg) / [after](after/dark/1440/home.jpg) | [before](../../baseline/light/375/home.jpg) / [after](after/light/375/home.jpg) | [before](../../baseline/light/768/home.jpg) / [after](after/light/768/home.jpg) | [before](../../baseline/light/1440/home.jpg) / [after](after/light/1440/home.jpg) |
| Leaderboard | [before](../../baseline/dark/375/leaderboard.jpg) / [after](after/dark/375/leaderboard.jpg) | [before](../../baseline/dark/768/leaderboard.jpg) / [after](after/dark/768/leaderboard.jpg) | [before](../../baseline/dark/1440/leaderboard.jpg) / [after](after/dark/1440/leaderboard.jpg) | [before](../../baseline/light/375/leaderboard.jpg) / [after](after/light/375/leaderboard.jpg) | [before](../../baseline/light/768/leaderboard.jpg) / [after](after/light/768/leaderboard.jpg) | [before](../../baseline/light/1440/leaderboard.jpg) / [after](after/light/1440/leaderboard.jpg) |
| Threat database | [before](../../baseline/dark/375/malicious_database.jpg) / [after](after/dark/375/malicious_database.jpg) | [before](../../baseline/dark/768/malicious_database.jpg) / [after](after/dark/768/malicious_database.jpg) | [before](../../baseline/dark/1440/malicious_database.jpg) / [after](after/dark/1440/malicious_database.jpg) | [before](../../baseline/light/375/malicious_database.jpg) / [after](after/light/375/malicious_database.jpg) | [before](../../baseline/light/768/malicious_database.jpg) / [after](after/light/768/malicious_database.jpg) | [before](../../baseline/light/1440/malicious_database.jpg) / [after](after/light/1440/malicious_database.jpg) |
| QR generator | [before](../../baseline/dark/375/generate_qr.jpg) / [after](after/dark/375/generate_qr.jpg) | [before](../../baseline/dark/768/generate_qr.jpg) / [after](after/dark/768/generate_qr.jpg) | [before](../../baseline/dark/1440/generate_qr.jpg) / [after](after/dark/1440/generate_qr.jpg) | [before](../../baseline/light/375/generate_qr.jpg) / [after](after/light/375/generate_qr.jpg) | [before](../../baseline/light/768/generate_qr.jpg) / [after](after/light/768/generate_qr.jpg) | [before](../../baseline/light/1440/generate_qr.jpg) / [after](after/light/1440/generate_qr.jpg) |
| Scan history | [before](../../baseline/dark/375/history_first_use.jpg) / [after](after/dark/375/history_first_use.jpg) | [before](../../baseline/dark/768/history_first_use.jpg) / [after](after/dark/768/history_first_use.jpg) | [before](../../baseline/dark/1440/history_first_use.jpg) / [after](after/dark/1440/history_first_use.jpg) | [before](../../baseline/light/375/history_first_use.jpg) / [after](after/light/375/history_first_use.jpg) | [before](../../baseline/light/768/history_first_use.jpg) / [after](after/light/768/history_first_use.jpg) | [before](../../baseline/light/1440/history_first_use.jpg) / [after](after/light/1440/history_first_use.jpg) |
| Admin users | [before](../../baseline/dark/375/admin_users.jpg) / [after](after/dark/375/admin_users.jpg) | [before](../../baseline/dark/768/admin_users.jpg) / [after](after/dark/768/admin_users.jpg) | [before](../../baseline/dark/1440/admin_users.jpg) / [after](after/dark/1440/admin_users.jpg) | [before](../../baseline/light/375/admin_users.jpg) / [after](after/light/375/admin_users.jpg) | [before](../../baseline/light/768/admin_users.jpg) / [after](after/light/768/admin_users.jpg) | [before](../../baseline/light/1440/admin_users.jpg) / [after](after/light/1440/admin_users.jpg) |

## Live request states

The [dark 375 px](states/dark/375/malicious_loading.jpg), [light 768 px](states/light/768/malicious_loading.jpg), and [dark 1440 px](states/dark/1440/malicious_loading.jpg) threat database captures show delayed API loading with matching skeleton rows. The same `states/<theme>/<width>/` directory contains `malicious_error`, `leaderboard_refresh`, `leaderboard_error`, `generator_busy`, and `scanner_progress` at every theme and width. These were captured against a local mock server with held or aborted requests; no live user data was involved.

Scan history and admin tables render with their page responses, so there is no later browser fetch or truthful skeleton stage for those views. Native form actions show a busy submit button and preserve the selected action value. The leaderboard starts with its server-rendered board, then shows a quiet refresh indicator or a retry notice without hiding existing rows.

## Checks

- Delayed and aborted API requests were inspected in Chromium at three widths and both themes.
- A browser exercise confirmed the threat database shows three skeleton rows during an actual delayed fetch, then an error with retry when the request fails.
- The scanner progress panel appears inside the form being submitted and has one live status message.
- The QR generator shows `aria-busy` and a spinner while its network request is pending.
- `UIStates.busy` restores the original button and keyboard focus after an async action.
## Account and consent recovery evidence

These matched viewport captures compare Phase 6 before the recovery fixes (`2681459`) with the fixes (`ab46275`). Each frame is 900 CSS pixels tall. All accounts are synthetic, both app servers run in `MOCK_MODE` with temporary SQLite databases and empty provider credentials, and the browser blocks external requests.

| State | Dark 375 | Dark 768 | Dark 1440 | Light 375 | Light 768 | Light 1440 |
|---|---|---|---|---|---|---|
| Go Ghost account check fails | [before](recovery/before/dark/375/go_ghost_check_failure.jpg) / [after](recovery/after/dark/375/go_ghost_check_failure.jpg) | [before](recovery/before/dark/768/go_ghost_check_failure.jpg) / [after](recovery/after/dark/768/go_ghost_check_failure.jpg) | [before](recovery/before/dark/1440/go_ghost_check_failure.jpg) / [after](recovery/after/dark/1440/go_ghost_check_failure.jpg) | [before](recovery/before/light/375/go_ghost_check_failure.jpg) / [after](recovery/after/light/375/go_ghost_check_failure.jpg) | [before](recovery/before/light/768/go_ghost_check_failure.jpg) / [after](recovery/after/light/768/go_ghost_check_failure.jpg) | [before](recovery/before/light/1440/go_ghost_check_failure.jpg) / [after](recovery/after/light/1440/go_ghost_check_failure.jpg) |
| Consent server returns 503 | [before](recovery/before/dark/375/consent_server_failure.jpg) / [after](recovery/after/dark/375/consent_server_failure.jpg) | [before](recovery/before/dark/768/consent_server_failure.jpg) / [after](recovery/after/dark/768/consent_server_failure.jpg) | [before](recovery/before/dark/1440/consent_server_failure.jpg) / [after](recovery/after/dark/1440/consent_server_failure.jpg) | [before](recovery/before/light/375/consent_server_failure.jpg) / [after](recovery/after/light/375/consent_server_failure.jpg) | [before](recovery/before/light/768/consent_server_failure.jpg) / [after](recovery/after/light/768/consent_server_failure.jpg) | [before](recovery/before/light/1440/consent_server_failure.jpg) / [after](recovery/after/light/1440/consent_server_failure.jpg) |
| Consent saved, browser cache blocked | [before](recovery/before/dark/375/consent_cache_blocked.jpg) / [after](recovery/after/dark/375/consent_cache_blocked.jpg) | [before](recovery/before/dark/768/consent_cache_blocked.jpg) / [after](recovery/after/dark/768/consent_cache_blocked.jpg) | [before](recovery/before/dark/1440/consent_cache_blocked.jpg) / [after](recovery/after/dark/1440/consent_cache_blocked.jpg) | [before](recovery/before/light/375/consent_cache_blocked.jpg) / [after](recovery/after/light/375/consent_cache_blocked.jpg) | [before](recovery/before/light/768/consent_cache_blocked.jpg) / [after](recovery/after/light/768/consent_cache_blocked.jpg) | [before](recovery/before/light/1440/consent_cache_blocked.jpg) / [after](recovery/after/light/1440/consent_cache_blocked.jpg) |

The Go Ghost pair shows the old workspace still visible despite its `hidden` attribute after a failed account check. The corrected state hides it, states that verification could not be confirmed, and offers **Reload and retry**. For consent, a server failure keeps the choice available; a successful server response with blocked local storage now says the choice was recorded and offers **Close**.

### Reproduce

From the Phase 6 worktree with the recovery fixes:

```bash
git worktree add --detach ../safescan-qr-ui-phase-6-visual-before 2681459
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
python docs/design/screenshots/ui-phase-6/capture_recovery.py --before-root ../safescan-qr-ui-phase-6-visual-before --after-root .
```

The script asserts each UI state before saving it. It starts both servers locally with isolated environment variables, induces `/api/me` network failure or a consent 503 response where needed, and blocks only the browser’s consent storage for the successful-save case. The generated [manifest](recovery/manifest.json) records the source commits and capture matrix.
