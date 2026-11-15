---
name: safescan-ship
description: Use when preparing a SafeScan website or backend change for PR, merge, or Render release. Covers focused verification, asset caching, and live checks.
---

# Ship a SafeScan change

Follow `AGENTS.md` for repository ownership and Render deployment. Keep each PR focused.

## Before the PR

- Run focused tests for the changed behavior. Run the full suite for application changes when practical; a documentation-only change needs focused validation instead.
- If a changed static asset is loaded through a versioned URL, update the cache key at each entry point that needs the change. Check direct template links and CSS imports. Avoid changing unrelated page cache keys.
- Check mobile callers before changing an API response. Keep JSON `error` values as plain strings.
- Review the staged diff for secrets, `.env` files, databases, model weights, and unrelated code.
- For a visible UI change, capture before and after evidence at the affected breakpoints and themes. Add physical-device evidence when browser chrome or camera hardware matters.
- State what was tested and what remains unverified in the PR.

## After merge

- Confirm the expected commit is live in Render and the changed page and assets load on `https://sqafe.com/` and the Render host.
- Check the changed user flow. If production behavior regresses, assess rollback promptly and tell the user what happened.
