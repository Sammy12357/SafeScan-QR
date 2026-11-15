# SafeScan — UI Polish Plan (for Codex)

**Repo:** `Sammy12357/SafeScan-QR`, audited at commit `83eed0a` (2026-11-14).
**Suggested location in repo:** `docs/plans/ui-polish.md`
**Scope:** five things, done as one consistent system and not page by page:

1. A spacing scale
2. Designed empty states
3. Proper loading states
4. Custom 404 (and other error) pages
5. Real error messages

Out of scope: new features, colour or brand redesign, risk scoring, payments logic, the mobile app.

---

## 0. Kickoff prompt (paste into Codex)

> Read `docs/plans/ui-polish.md` and `AGENTS.md`. Implement the phases in §6 in order, one PR per phase, on branches `codex/ui-phase-N`.
>
> Before Phase 1, do the research in §7 and write `docs/design/research-log.md` (source, link, date, what you took from it). Where your research disagrees with a default in this plan, follow the better-supported choice and record why in the log and the PR description.
>
> Rules:
> - Keep the site build-free: plain CSS and JS, Jinja templates, no bundler, no CSS framework, no third-party scripts or fonts beyond what is already loaded.
> - Do not change the JSON key `error` (a string) in API responses. The mobile app reads it. Add new fields beside it.
> - No visual change may be merged without before/after screenshots at 375, 768 and 1440 px, in dark and light theme, attached to the PR.
> - Every state you add must work with a keyboard and a screen reader, and respect `prefers-reduced-motion`.
> - Bump the `?v=` query strings in templates for every static file you change.
> - Run `python -m pytest tests -q` before each PR.
> - Don't stop to ask questions. §9 lists the defaults to use.

---

## 1. Audit: where things stand

### 1.1 Spacing

- `static/styles-base.css` defines tokens for colour, shadow, radius, easing and fonts. **There are no spacing tokens.**
- Across the 8 stylesheets (1,436 lines), `padding`, `margin` and `gap` use **35 different values**. Most used: 14px (85 times), 10px (69), 12px (67), 18px (62), 8px (54), 16px (49), 6px (28), 22px (18), 24px (17), 20px (17). There are also one-offs such as 5, 7, 9, 11, 13, 15, 26, 34, 42, 46, 54 and 92px.
- Five templates carry their own `<style>` blocks (`history.html`, `leaderboard.html`, `malicious_database.html`, `profile.html`, `login.html`) and five have inline `style=""` attributes. These bypass the shared stylesheets.
- The admin area has its own token set (`--admin-*` in `admin.css`) and its own spacing.

### 1.2 Empty states

| Page | Today |
|---|---|
| History | One grey line: "No scans yet. Scan a QR code to see history here." Signed-out users get a grey line with a link styled inline |
| Leaderboard | One grey line, toggled with `style.display` |
| Malicious database | One line of text in `.mq-state`; has separate wording for "no results for your search" and "no data yet" (good) |
| Admin tables | Only the waitlist table says anything when empty. The others render a header row and nothing else |
| Profile, Go Ghost, token, plans | Not audited in detail. Codex to inventory |

No page has an icon, a heading, or a button that takes the user to the next step.

### 1.3 Loading states

| Place | Today |
|---|---|
| Scanner | A text line that cycles through steps (`loadingSteps` in `app-core.js`). The scan itself is a full-page form POST, so the user waits on a frozen page |
| History | Text only |
| Leaderboard | None. The refresh fetch fails silently (`.catch(function () {})`) |
| Malicious database | "Loading the threat database…" text; pager buttons are disabled while loading (good) |
| Buttons | Only some are disabled while their request runs, so double submits are possible |
| Anywhere | No skeletons, no `aria-busy`, no shared spinner or button-busy style |

### 1.4 Error pages

- `hackabull/app_module.py` L407–429: every error handler returns JSON, for every request. A person who opens a wrong link sees `{"error":"Not found."}` in the browser. The same goes for 403, 429 and 500.
- The site uses many full-page form POSTs (scan, username, waitlist, data request, logout, all admin actions). When one of them raises `SafeScanError` or hits a rate limit, **the browser navigates to a page of raw JSON**.
- The 500 handler logs with `print` and gives the user no reference to quote.

### 1.5 Error messages

- Generic: "Something went wrong on our end.", "Invalid request.", "Error loading history. Please try again later."
- Internal names shown to users: "ALPHA_SOLANA_RECIPIENT is not a valid Solana address.", "ALPHA_SOLANA_PRICE_USD must be greater than 0.", "Unexpected fields: …", "Solana RPC error: {upstream text}".
- Five `window.alert()` calls in `app-core.js` (wallet and camera).
- Errors reach the user in at least four ways: alert, toast (`showCopyToast`), inline text, and query-string messages (`/profile?error=…`). No shared component.
- Some messages are already good and should be kept as models: "Uploaded file is too large. Use a file under N MB.", "This Solana payment quote expired. Open the payment page to generate a fresh quote."

---

## 2. The system to build

### 2.1 Spacing scale

Add to `:root` in `static/styles-base.css` (4px base):

| Token | Value | Typical use |
|---|---|---|
| `--space-0` | 0 | |
| `--space-1` | 2px | hairline nudges only |
| `--space-2` | 4px | icon-to-text gap, tight chips |
| `--space-3` | 8px | inside small controls, list item gaps |
| `--space-4` | 12px | form field gaps, button padding (vertical) |
| `--space-5` | 16px | default gap, card padding on mobile, button padding (horizontal) |
| `--space-6` | 20px | |
| `--space-7` | 24px | card padding on desktop, gap between cards |
| `--space-8` | 32px | between sections inside a page |
| `--space-9` | 40px | |
| `--space-10` | 48px | page section spacing |
| `--space-11` | 64px | hero and empty-state breathing room |
| `--space-12` | 96px | top-of-page hero only |

Semantic aliases, so pages don't choose numbers:

```css
--gap-inline: var(--space-3);      /* between items in a row */
--gap-stack: var(--space-5);       /* between stacked blocks */
--gap-section: var(--space-10);    /* between page sections */
--pad-control-y: var(--space-4);
--pad-control-x: var(--space-5);
--pad-card: var(--space-7);
--pad-page: clamp(var(--space-5), 4vw, var(--space-8));
```

Migration map for existing values (use judgement by context, then check the screenshot):

| Old | New |
|---|---|
| 1–3px | `--space-1` (or keep as a border/offset, not spacing) |
| 4, 5px | `--space-2` |
| 6, 7px | `--space-2` in tight chips, `--space-3` elsewhere |
| 8, 9px | `--space-3` |
| 10, 11px | `--space-3` for gaps, `--space-4` for padding |
| 12, 13px | `--space-4` |
| 14, 15px | `--space-5` (use `--space-4` if the element becomes visibly looser) |
| 16px | `--space-5` |
| 18, 20px | `--space-6` |
| 22, 24, 26px | `--space-7` |
| 28, 30, 32, 34, 36px | `--space-8` |
| 40, 42, 44, 46px | `--space-9` |
| 48, 50, 54, 56px | `--space-10` |
| 60, 64px | `--space-11` |
| 92px | `--space-12` |

Rules:
- `padding`, `margin`, `gap`, `row-gap`, `column-gap` and `inset` use tokens only. Borders, outlines, font sizes and fixed component dimensions are not spacing and stay as they are.
- Prefer `gap` on a flex or grid parent over margins on children.
- Admin uses the same scale; it may map to tighter aliases (`--pad-card: var(--space-5)`).
- Add radius and type tokens only if research shows a clear need. Don't widen scope.

Enforcement: `tests/test_css_spacing_tokens.py` parses `static/*.css` (excluding `vendor/`) and template `<style>` blocks, and fails on any raw length in a spacing property. It takes a short, commented allowlist for genuine exceptions.

### 2.2 Shared state components

One stylesheet, `static/styles-states.css`, imported by `styles.css` and by `admin.css`. One script, `static/ui-states.js`, loaded before page scripts. Jinja macros in `templates/_states.html` for server-rendered use.

**Empty state**

```html
<section class="state state-empty" role="status">
  <svg class="state-icon" aria-hidden="true">…</svg>
  <h2 class="state-title">No scans yet</h2>
  <p class="state-body">Scan a QR code and it will show up here with its verdict.</p>
  <a class="primary-button" href="/">Scan a QR code</a>
</section>
```

- Macro: `{{ empty_state(icon, title, body, action_label, action_href, secondary) }}`. JS: `UIStates.empty(container, {...})`.
- Three kinds, with different wording: **first use** (nothing created yet → explain and offer the first action), **no results** (a search or filter matched nothing → show the query, offer "Clear filters"), **no access** (signed out or not allowed → offer sign-in).
- Icons: a small inline SVG set in `static/icons/`, single colour using `currentColor`. No icon font, no emoji.
- Compact variant (`.state-compact`) for tables and side panels.

**Loading**

| Situation | Pattern |
|---|---|
| Under about 300 ms | Show nothing (avoid flicker). `UIStates.loading()` delays its indicator |
| Content loading into a known layout (lists, tables, cards) | Skeleton rows that match the final layout: `.skeleton`, `.skeleton-line`, `.skeleton-row` |
| A button's own action | Button busy state: `aria-busy="true"`, `disabled`, inline spinner, label changes ("Saving…"). `UIStates.busy(button, promise)` restores it and prevents double submits |
| Long work with real stages (scan) | Step list with the current step marked, as today, inside a proper panel with a spinner and "This usually takes a few seconds" |
| Over about 10 s | Add "Still working…" and, where possible, a cancel button |
| Full-page navigation after a form POST | Disable the submit button and show its busy state on `submit` |

- Containers set `aria-busy="true"` while loading. A visually hidden `role="status"` region announces "Loading scan history" once, and "Loaded" is not announced.
- Skeleton shimmer is disabled under `prefers-reduced-motion: reduce` (static grey blocks instead).
- A loading state always ends in content, empty or error. Add a timeout (default 15 s) that turns it into an error with a retry button.

**Error (inline)**

```html
<section class="state state-error" role="alert">
  <svg class="state-icon" aria-hidden="true">…</svg>
  <h2 class="state-title">Scan history didn't load</h2>
  <p class="state-body">Check your connection and try again.</p>
  <button class="primary-button" data-retry>Try again</button>
  <p class="state-ref">Reference: 7F3K-21QX</p>
</section>
```

- `UIStates.error(container, {title, body, retry, ref})`.
- Field errors: text directly under the field, linked with `aria-describedby`, field gets `aria-invalid="true"`. On submit failure, focus moves to the first invalid field. Forms with several errors get a summary at the top that links to each field.
- Banner (`.notice`, variants info / success / warning / danger) for page-level messages that came from a redirect.
- Toast for brief confirmations only ("Copied"). Errors never appear only as a toast.
- Replace all `window.alert()` calls.

### 2.3 Error pages

Templates: `templates/errors/404.html`, `403.html`, `429.html`, `500.html`, `503.html`, all extending one `errors/_base.html` that includes the normal top nav and footer.

| Page | Title | Body | Actions |
|---|---|---|---|
| 404 | "We can't find that page" | "The link may be old or mistyped." | Scan a QR code · Scan history · Learn · Home |
| 403 | "You don't have access to this page" | Signed out → "Sign in to continue." Signed in → "This area is for admins." | Sign in / Home |
| 429 | "You're going a bit fast" | "Try again in N seconds." (from `Retry-After`, counting down) | Try again (enabled when the timer ends) |
| 500 | "Something broke on our side" | "It's not you. We've logged it. Try again in a minute." | Try again · Home · Reference code |
| 503 | "SafeScan is briefly unavailable" | "We're restarting or updating. This usually takes under a minute." | Try again |
| Offline (client) | "You're offline" | Shown by `ui-states.js` when `fetch` fails and `navigator.onLine` is false | Retry when back online |

Rules:
- **Content negotiation** in the exception handlers: return JSON when the path starts with `/api/`, `/webhooks/`, `/metrics` or `/health`, or when `Accept` prefers `application/json`, or when the request has `X-Requested-With: fetch` (set by a shared `UIStates.fetchJson` helper). Otherwise render the HTML page with the right status code.
- Error pages must render without a database or a session (they are shown when those fail). Wrap user-context lookups in a try/except and fall back to the signed-out nav.
- Error pages send `Cache-Control: no-store` and `<meta name="robots" content="noindex">`.
- The 404 page never echoes the requested path into HTML.
- Admin paths get the same pages inside the public shell (don't reveal admin layout to signed-out users).
- **Form POST failures should not land on an error page at all.** Validation problems re-render the same form with the user's input kept and inline errors. Use post/redirect/get with a one-time flash message for success. Error pages are for when there is no form to return to.

### 2.4 Error message contract

**API shape (backward compatible):**

```json
{
  "error": "That file is too large. Choose an image under 10 MB.",
  "code": "upload_too_large",
  "hint": "Crop or compress the image, then try again.",
  "field": "file",
  "request_id": "7F3K-21QX"
}
```

- `error` stays a plain string. `code`, `hint`, `field`, `request_id` are new and optional.
- `SafeScanError(message, status_code, *, code=None, hint=None, field=None)`. Existing call sites keep working.
- A request-ID middleware creates a short ID per request, adds it to the response header `X-Request-ID`, to every error body, and to the log line. Replace the `print` in the 500 handler with structured logging that includes the ID and never the request body.

**Catalogue:** `hackabull/errors.py` holds every user-facing message keyed by `code`, so wording lives in one place:

```python
ERRORS = {
  "upload_too_large": Msg("That file is too large.", "Choose an image under {limit} MB.", 413),
  "qr_not_found":     Msg("We couldn't find a QR code in that image.", "Try a sharper, closer photo with the whole code in frame.", 422),
  "rate_limited":     Msg("You're going a bit fast.", "Try again in {seconds} seconds.", 429),
  ...
}
```

**Writing rules** (apply to every message, server and client):

1. Say what happened, in the user's terms. "We couldn't read that QR code", not "Decode failed".
2. Say what to do next, specifically. "Use a file under 10 MB", not "Please try again later".
3. Don't blame the user. "That link isn't a web address we can check", not "Invalid URL".
4. No internal names: no env vars, table names, stack traces, provider error text, or HTTP jargon. Configuration faults show "This feature isn't available right now" to users and log the detail for the owner.
5. One or two short sentences. Sentence case. No exclamation marks, no "Oops".
6. Keep safety wording honest: a scan that couldn't complete is "We couldn't finish checking this link", never anything that reads as "safe".
7. Security-sensitive messages stay deliberately vague where they must ("Email or password is incorrect"). Don't make login or reset errors more specific.

**Rewrites for messages found in the audit:**

| Now | Becomes |
|---|---|
| "Something went wrong on our end." | "Something broke on our side. Try again in a minute. Reference: {id}" |
| "Invalid request." | The specific cause, or "We couldn't process that. Refresh the page and try again." |
| "Error loading history. Please try again later." | "Your scan history didn't load. Check your connection and try again." + Retry button |
| "ALPHA_SOLANA_RECIPIENT is not a valid Solana address." (and the other env-var messages) | User: "Solana payments aren't available right now." Log: the original text |
| "Solana RPC error: {upstream}" | "We couldn't reach the Solana network. Try again in a moment." |
| "Unexpected fields: a, b" | "We couldn't process that. Refresh the page and try again." (log the field names) |
| "Not found." (JSON) | 404 page for browsers; `{"error":"We can't find that.","code":"not_found"}` for API |
| "Too many requests. Please slow down." | "You're going a bit fast. Try again in {seconds} seconds." with `Retry-After` |
| "No QR code or valid payload detected in this file." | "We couldn't find a QR code in that file. Try a sharper photo with the whole code in frame." |
| `window.alert("Camera scanner is still loading…")` | Inline status under the camera button, button shows busy state until ready |

---

## 3. Page-by-page inventory (Codex completes this first)

Create `docs/design/state-inventory.md` with one row per view and fill every cell. Starting point:

| View | Loading | Empty | Error | Notes |
|---|---|---|---|---|
| Home / scanner (`index.html`) | Step panel + busy submit buttons | n/a | Inline panel for decode failures; never raw JSON | Largest surface; do first |
| Scan result | Skeleton if any part loads late | "No risk signals found" must not read as a guarantee | Partial-result notice when a provider failed | |
| History | Skeleton rows | First use; signed out | Inline + retry | Move `<style>` block out |
| Leaderboard | Skeleton rows on first load | First use | Quiet "Couldn't refresh. Showing the last results." | Stop swallowing errors |
| Malicious database | Skeleton rows | First use; no results for "{query}" + Clear | Inline + retry | |
| Profile | Busy buttons | No wallet linked; no Discord linked | Banner from redirects; inline field errors | |
| Go Ghost | Per-broker status | No profile yet; nothing found | Per-broker error with manual fallback | Coordinate with the Go Ghost plan |
| Generate QR | Busy button | Before first generation | Inline | |
| Login / onboarding / data request / waitlist | Busy submit | n/a | Inline field errors, input preserved | |
| Token, plans, learn, legal | n/a or busy buttons | n/a | Banner | |
| Admin: users, scans, waitlist, blocklist, reports, fraud, audit, API keys | Busy buttons | Compact empty state in every table ("No reports to review") | Banner after failed action | 8+ tables |

---

## 4. Accessibility requirements

- Loading containers: `aria-busy`; one polite announcement.
- Errors that appear after an action: `role="alert"`; focus moves to the error or the first invalid field.
- Empty states: `role="status"`; real headings in the page outline.
- Colour is never the only signal: icon and text accompany red/green.
- Text contrast at least 4.5:1 in both themes, including muted text in empty states.
- Buttons and links in state components are at least 44×44 px on touch layouts.
- All motion respects `prefers-reduced-motion`.

---

## 5. Testing

**Automated**
- `tests/test_css_spacing_tokens.py`: no raw spacing values (see §2.1).
- `tests/test_error_pages.py`:
  - `GET /nope` with a browser `Accept` → 404, HTML, contains the nav and the title, no JSON.
  - `GET /api/nope` → 404 JSON with `error` (string) and `code`.
  - `Accept: application/json` on a page path → JSON.
  - A route that raises → 500 HTML with a reference code that matches `X-Request-ID`; body contains no exception text.
  - 429 response carries `Retry-After`.
  - Error pages render when the session lookup raises.
- `tests/test_error_messages.py`: every catalogue entry has a message and a hint; no message contains an upper-case env-style token, "Traceback", "Exception", or "undefined"; every `SafeScanError(` call site uses a catalogue code or is on a short allowlist.
- `tests/test_ui_states_static.py`: no `window.alert(` in `static/*.js`; every `fetch(` in page scripts goes through `UIStates.fetchJson` or has an explicit catch that renders an error state; no empty `.catch(function () {})`.
- Template test: no `<style>` blocks and no `style=""` attributes in `templates/` (short allowlist for dynamic values such as progress widths, which should use CSS custom properties).
- Mobile contract test: API error bodies still have `error` as a string.

**Visual**
- `scripts/ui_screenshots.py` (Playwright, dev dependency only): starts the app in `MOCK_MODE`, visits every view in each state (loading, empty, error, content) using a `?__state=` switch that is honoured only when `MOCK_MODE=true`, and saves screenshots at 375, 768 and 1440 px in both themes to `.cache/ui-shots/<git-sha>/`. PRs attach before/after pairs.
- Add a test that `?__state=` does nothing when `MOCK_MODE` is off.

**Manual, per PR**
- Keyboard-only pass and a screen-reader pass (VoiceOver or NVDA) on the changed views.
- Throttle to "Slow 4G" in DevTools and confirm loading states appear and never flicker on fast responses.
- Go offline mid-action.

---

## 6. Phases

| # | Phase | Size | Contents |
|---|---|---|---|
| 0 | Research and inventory | S | §7 research log; complete `docs/design/state-inventory.md`; screenshot script; baseline screenshots of every view |
| 1 | Spacing tokens | S | Add tokens and aliases to `styles-base.css`; add `docs/design/spacing.md`; no visual change yet |
| 2 | Spacing migration | L | Convert stylesheets one file per commit: base → layout → panels → scanner → go-ghost → theme-light → admin. Move template `<style>` blocks and inline styles into stylesheets. Turn on the spacing test. Screenshot diffs for every view |
| 3 | State components | M | `styles-states.css`, `ui-states.js`, `_states.html` macros, icon set; a hidden `/__states` gallery page (only in `MOCK_MODE`) showing every component and variant |
| 4 | Error foundation | M | Request-ID middleware; `SafeScanError` extensions; `hackabull/errors.py` catalogue; content negotiation; error page templates; structured logging in the 500 handler; tests |
| 5 | Error messages | M | Rewrite every server and client message to the catalogue and writing rules; remove `window.alert`; inline field errors and input preservation on all forms; banner for redirect messages |
| 6 | Loading states | M | Skeletons for history, leaderboard, malicious database, admin tables; busy buttons everywhere; scanner step panel; timeouts and retry; offline handling |
| 7 | Empty states | M | Every row of the inventory, including all admin tables and the signed-out variants |
| 8 | Accessibility and QA | S | §4 checks on every view; fix contrast and focus issues found; final screenshot set; update `docs/design/` |

Phases 1–2 and 3–4 don't depend on each other and can run in parallel. Phases 5–7 need 3 and 4.

**Definition of done**
- Zero raw spacing values outside the allowlist; the test is in CI.
- No browser request can produce a JSON error page.
- Every row in the state inventory has a designed loading, empty and error state, shown in the gallery.
- No `window.alert`, no silent `catch`, no message exposing internals.
- 500 responses carry a reference code that appears in the logs.
- The mobile app's error handling is unaffected.

---

## 7. Research mandate (Codex does this itself)

Look these up from primary sources, log them, and adjust the defaults above where the evidence is better. The numbers in this plan (300 ms delay, 15 s timeout, 4px base, 44 px targets) are starting points to confirm.

| Topic | What to find out | Suggested sources |
|---|---|---|
| Spacing systems | Base unit, number of steps, naming, fluid spacing with `clamp()` | Material Design, IBM Carbon, Shopify Polaris, GitHub Primer, Tailwind's scale, Open Props, Every Layout |
| Empty states | Types, anatomy, wording, when to include an action | Carbon, Polaris, Primer, Atlassian design guidelines, Nielsen Norman Group |
| Loading | Skeleton vs spinner vs progress; response-time thresholds; avoiding flicker; announcing to assistive tech | Nielsen Norman Group on response times and skeleton screens, Carbon and Polaris loading guidance, WAI-ARIA `aria-busy` and live-region guidance |
| Error messages | Structure, tone, placement, error summaries, preserving input | GOV.UK Design System (error message, error summary), Nielsen Norman Group error-message guidelines, WCAG 2.2 criteria 3.3.1, 3.3.3, 4.1.3 |
| Error pages | What a useful 404 and 500 contain; status codes and caching; `Retry-After` | MDN HTTP status reference, Google Search Central on soft 404s, Starlette/FastAPI exception-handler docs |
| API errors | Whether to align new fields with RFC 9457 (Problem Details) without breaking the `error` string | RFC 9457 |
| Accessibility | Target size (WCAG 2.5.8), focus management after errors, reduced motion | WCAG 2.2, WAI-ARIA Authoring Practices |
| This codebase | Anything the audit above missed: grep every `fetch(`, every `raise`, every template branch on empty data | The repo |

Also free to add, if research supports it and it stays within scope: a type scale, a `:focus-visible` audit, a `<noscript>` message for JS-dependent pages, print styles for scan results, and a favicon or title change on error pages. Log each addition in the research log with its reason.

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Spacing migration shifts layouts in small ways across many pages | One stylesheet per commit; screenshot diffs at three widths and two themes; when in doubt pick the token nearest the old value |
| Content negotiation breaks a client that expects JSON from a page path | Decide by path prefix first, then `Accept`; test the mobile app's endpoints explicitly |
| Friendlier errors hide information you need for debugging | Request ID links the user-facing message to a full structured log entry |
| Skeletons cause layout shift | Skeleton dimensions come from the same CSS as real rows |
| Scope creep into a redesign | Colour, type and component shapes stay as they are unless a change is required by this plan |

---

## 9. Defaults (no need to ask Sam)

| Decision | Default |
|---|---|
| Spacing base | 4px, the 13 steps in §2.1 |
| Icons | Small inline SVG set in `static/icons/`, `currentColor` |
| Tone | Plain, calm, second person; no jokes on error pages |
| Reference code format | 8 characters, upper-case letters and digits, shown as `XXXX-XXXX` |
| Loading indicator delay / timeout | 300 ms / 15 s |
| Where form errors show | Inline under the field, plus a summary when there are two or more |
| State gallery and `?__state=` switch | Available only when `MOCK_MODE=true` |
| Illustration | None beyond icons |
| Admin | Same components, compact variants |
