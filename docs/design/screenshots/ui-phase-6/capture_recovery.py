#!/usr/bin/env python3
"""Capture Phase 6 recovery states from two isolated local mock worktrees.

This script uses synthetic accounts, temporary SQLite databases, and the
credential-free environment from scripts/ui_screenshots.py. Browser requests
outside each local server are blocked.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from scripts.ui_screenshots import (  # noqa: E402
    context_for,
    free_port,
    git_sha,
    isolated_server_env,
    wait_for_server,
)


STATES = ("go_ghost_check_failure", "consent_server_failure", "consent_cache_blocked")
WIDTHS = (375, 768, 1440)
THEMES = ("dark", "light")


def local_requests_only(context, base_url: str) -> None:
    def handle(route):
        url = route.request.url
        if url.startswith(base_url + "/") or url.startswith(("data:", "blob:")):
            route.continue_()
        else:
            route.abort("blockedbyclient")

    context.route("**/*", handle)


def new_context(browser, base_url: str, width: int, theme: str, storage_state=None, hide_cookie_banner=False):
    context = browser.new_context(
        base_url=base_url,
        viewport={"width": width, "height": 900},
        device_scale_factor=1,
        reduced_motion="reduce",
        storage_state=storage_state,
    )
    local_requests_only(context, base_url)
    context.add_init_script("localStorage.setItem('safescan_theme', " + json.dumps(theme) + ");")
    if hide_cookie_banner:
        context.add_init_script("""
            localStorage.setItem('safeScanConsent', JSON.stringify({
                consentType: 'essential_only', bannerVersion: 'consent-v1',
                timestamp: new Date().toISOString()
            }));
        """)
    return context


def go_ghost_check_failure(browser, base_url: str, width: int, theme: str, phase: str, member_state):
    context = new_context(browser, base_url, width, theme, member_state, hide_cookie_banner=True)
    try:
        page = context.new_page()
        page.goto("/go-ghost", wait_until="domcontentloaded")
        page.wait_for_timeout(400)  # Let the normal first account check settle.
        page.locator("#startGoGhostButton").click()
        page.locator("#ghostFirstNameInput").fill("Casey")
        page.locator("#ghostLastNameInput").fill("Example")
        assert page.locator("#goGhostWorkspace").is_visible()

        page.route("**/api/me", lambda route: route.abort("failed"))
        page.evaluate("() => checkGhostAccount()")
        notice = page.locator("#goGhostSessionNotice")
        notice.wait_for(state="visible")
        if phase == "before":
            assert "sign-in changed" in notice.inner_text().lower()
            assert page.locator("#goGhostSessionRetryButton").count() == 0
            assert page.locator("#goGhostWorkspace").is_visible(), "Baseline must show the overridden hidden attribute"
        else:
            assert "couldn't confirm your sign-in" in notice.inner_text().lower()
            assert page.locator("#goGhostSessionRetryButton").is_visible()
            assert page.locator("#goGhostWorkspace").is_hidden(), "Private workspace must be visually hidden"
        assert page.locator("#ghostFirstNameInput").input_value() == ""
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(100)
        return page.screenshot(type="jpeg", quality=85, animations="disabled")
    finally:
        context.close()


def consent_server_failure(browser, base_url: str, width: int, theme: str, _phase: str, _member_state):
    context = new_context(browser, base_url, width, theme)
    try:
        page = context.new_page()
        page.route("**/api/consent", lambda route: route.fulfill(
            status=503, body='{"error":"Unavailable"}', content_type="application/json"
        ))
        page.goto("/", wait_until="domcontentloaded")
        page.locator("[data-consent-choice='essential_only']").click()
        feedback = page.locator("#consentSaveFeedback")
        feedback.wait_for(state="visible")
        assert page.locator("#cookieConsentBanner").is_visible()
        assert page.locator("[data-consent-choice='essential_only']").is_enabled()
        return page.screenshot(type="jpeg", quality=85, animations="disabled")
    finally:
        context.close()


def consent_cache_blocked(browser, base_url: str, width: int, theme: str, phase: str, _member_state):
    context = new_context(browser, base_url, width, theme)
    context.add_init_script("""
        const originalSetItem = Storage.prototype.setItem;
        Storage.prototype.setItem = function(key, value) {
            if (key === 'safeScanConsent' || key === 'safeScanConsentId') {
                throw new DOMException('Storage blocked', 'QuotaExceededError');
            }
            return originalSetItem.call(this, key, value);
        };
    """)
    try:
        page = context.new_page()
        page.goto("/", wait_until="domcontentloaded")
        with page.expect_response("**/api/consent") as saved:
            page.locator("[data-consent-choice='essential_only']").click()
        assert saved.value.status == 200
        if phase == "before":
            feedback = page.locator("#consentSaveFeedback")
            feedback.wait_for(state="visible")
            assert "couldn't save" in feedback.inner_text().lower()
        else:
            page.locator(".consent-title").get_by_text("Privacy choice recorded").wait_for()
            assert "couldn't remember it" in page.locator(".consent-copy").inner_text().lower()
            assert page.get_by_role("button", name="Close", exact=True).is_visible()
            assert page.locator("#consentSaveFeedback").count() == 0
        return page.screenshot(type="jpeg", quality=85, animations="disabled")
    finally:
        context.close()


CAPTURE = {
    "go_ghost_check_failure": go_ghost_check_failure,
    "consent_server_failure": consent_server_failure,
    "consent_cache_blocked": consent_cache_blocked,
}


def capture_phase(browser, phase: str, app_root: Path, output: Path, widths, themes, states):
    with tempfile.TemporaryDirectory(prefix=f"safescan-ui-{phase}-") as temp_dir:
        port = free_port()
        base_url = f"http://localhost:{port}"
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
            cwd=app_root,
            env=isolated_server_env(temp_dir, base_url),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_server(base_url, process)
            member_state = None
            if "go_ghost_check_failure" in states:
                seed = context_for(browser, base_url, "member")
                try:
                    member_state = seed.storage_state()
                finally:
                    seed.close()
            for theme in themes:
                for width in widths:
                    for state in states:
                        image = CAPTURE[state](browser, base_url, width, theme, phase, member_state)
                        path = output / phase / theme / str(width) / f"{state}.jpg"
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(image)
                        print(path.relative_to(output))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-root", type=Path, required=True, help="Worktree at the pre-fix Phase 6 commit")
    parser.add_argument("--after-root", type=Path, default=ROOT, help="Worktree with the Phase 6 fixes")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/design/screenshots/ui-phase-6/recovery")
    parser.add_argument("--widths", nargs="+", type=int, default=WIDTHS)
    parser.add_argument("--themes", nargs="+", choices=THEMES, default=THEMES)
    parser.add_argument("--states", nargs="+", choices=STATES, default=STATES)
    args = parser.parse_args()
    before_root = args.before_root.resolve()
    after_root = args.after_root.resolve()
    output = args.output.resolve()
    for app_root in (before_root, after_root):
        if not (app_root / "AGENTS.md").is_file():
            parser.error(f"Not a SafeScan worktree: {app_root}")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Install development dependencies from requirements-dev.txt and Chromium") from exc

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            capture_phase(browser, "before", before_root, output, args.widths, args.themes, args.states)
            capture_phase(browser, "after", after_root, output, args.widths, args.themes, args.states)
        finally:
            browser.close()
    (output / "manifest.json").write_text(json.dumps({
        "before_commit": git_sha(before_root),
        "after_commit": git_sha(after_root),
        "mode": "local MOCK_MODE servers, synthetic account, external requests blocked",
        "widths": args.widths,
        "themes": args.themes,
        "states": args.states,
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
