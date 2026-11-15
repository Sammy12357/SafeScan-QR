"""Browser checks for account recheck privacy and consent save feedback."""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from scripts.ui_screenshots import context_for, free_port, isolated_server_env, wait_for_server


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def browser_site():
    playwright_api = pytest.importorskip("playwright.sync_api")
    with tempfile.TemporaryDirectory(prefix="safescan-ui-recovery-") as temp_dir:
        port = free_port()
        base_url = f"http://localhost:{port}"
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
            cwd=ROOT,
            env=isolated_server_env(temp_dir, base_url),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_server(base_url, process)
            with playwright_api.sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(headless=True)
                except playwright_api.Error as exc:
                    pytest.skip(f"Chromium unavailable for browser check: {exc}")
                try:
                    yield browser, base_url
                finally:
                    browser.close()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


def test_go_ghost_network_failure_hides_details_and_offers_retry(browser_site):
    browser, base_url = browser_site
    context = context_for(browser, base_url, "member")
    try:
        page = context.new_page()
        page.goto("/go-ghost", wait_until="domcontentloaded")
        page.locator("#startGoGhostButton").click()
        page.locator("#ghostFirstNameInput").fill("Private")
        assert page.locator("#goGhostWorkspace").is_visible()

        page.route("**/api/me", lambda route: route.abort("failed"))
        page.evaluate("() => checkGhostAccount()")
        assert page.locator("#goGhostWorkspace").is_hidden()
        assert page.locator("#ghostFirstNameInput").input_value() == ""
        assert "couldn't confirm your sign-in" in page.locator("#goGhostSessionNotice").inner_text()
        assert page.locator("#goGhostSessionRetryButton").is_visible()
        assert page.locator("#goGhostAccountCheckStatus").is_hidden()

        page.unroute("**/api/me")
        with page.expect_navigation():
            page.locator("#goGhostSessionRetryButton").click()
        page.locator("#goGhostWorkspace").wait_for(state="visible")
        assert page.locator("#goGhostWorkspace").is_visible()
    finally:
        context.close()


def test_consent_success_with_blocked_storage_is_reported_as_recorded(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url)
    try:
        page = context.new_page()
        page.add_init_script("""
            const originalSetItem = Storage.prototype.setItem;
            Storage.prototype.setItem = function(key, value) {
                if (key === 'safeScanConsent' || key === 'safeScanConsentId') {
                    throw new DOMException('Storage blocked', 'QuotaExceededError');
                }
                return originalSetItem.call(this, key, value);
            };
        """)
        page.goto("/", wait_until="domcontentloaded")
        with page.expect_response("**/api/consent") as saved:
            page.locator("[data-consent-choice='essential_only']").click()
        assert saved.value.status == 200
        page.get_by_text("Privacy choice recorded", exact=True).wait_for()
        assert page.locator(".consent-title").inner_text() == "Privacy choice recorded"
        assert "couldn't remember it" in page.locator(".consent-copy").inner_text()
        assert page.locator("#consentSaveFeedback").count() == 0
        assert page.locator("#cookieConsentBanner").is_visible()
        page.get_by_role("button", name="Close", exact=True).click()
        assert page.locator("#cookieConsentBanner").is_hidden()
    finally:
        context.close()


def test_consent_choice_survives_optional_id_storage_failure(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url)
    try:
        page = context.new_page()
        page.add_init_script("""
            const originalSetItem = Storage.prototype.setItem;
            Storage.prototype.setItem = function(key, value) {
                if (key === 'safeScanConsentId') throw new DOMException('Storage blocked', 'QuotaExceededError');
                return originalSetItem.call(this, key, value);
            };
        """)
        page.goto("/", wait_until="domcontentloaded")
        with page.expect_response("**/api/consent") as saved:
            page.locator("[data-consent-choice='essential_only']").click()
        assert saved.value.status == 200
        page.locator("#cookieConsentBanner").wait_for(state="hidden")
        assert page.locator("#cookieConsentBanner").is_hidden()
        assert page.evaluate("localStorage.getItem('safeScanConsent')") is not None
        assert page.locator(".consent-title").inner_text() == "Privacy preferences"
    finally:
        context.close()


def test_consent_server_failure_keeps_choice_available(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url)
    try:
        page = context.new_page()
        page.route("**/api/consent", lambda route: route.fulfill(status=503, body='{"error":"Unavailable"}', content_type="application/json"))
        page.goto("/", wait_until="domcontentloaded")
        page.locator("[data-consent-choice='essential_only']").click()
        page.locator("#consentSaveFeedback").wait_for(state="visible")
        assert page.locator("#consentSaveFeedback").is_visible()
        assert "couldn't confirm" in page.locator("#consentSaveFeedback").inner_text()
        assert page.locator("[data-consent-choice='essential_only']").is_visible()
        assert page.locator("#cookieConsentBanner").is_visible()
    finally:
        context.close()


def test_gpc_overrides_prior_all_choice_in_browser_and_server(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url, extra_http_headers={"Sec-GPC": "1"})
    try:
        page = context.new_page()
        page.add_init_script("""
            Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', {get: () => true});
            localStorage.setItem('safeScanConsent', JSON.stringify({
                consentType: 'all', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()
            }));
        """)
        page.goto("/", wait_until="domcontentloaded")
        assert page.locator("#cookieConsentBanner").is_visible()
        assert page.locator('[data-consent-choice="all"]').is_hidden()
        assert page.locator('[data-consent-choice="custom"]').is_hidden()
        assert "Global Privacy Control is on" in page.locator(".consent-copy").inner_text()
        with page.expect_response("**/api/consent") as saved:
            page.locator('[data-consent-choice="essential_only"]').click()
        assert saved.value.json()["effectiveConsentType"] == "essential_only"
        assert page.evaluate("JSON.parse(localStorage.getItem('safeScanConsent')).consentType") == "essential_only"
    finally:
        context.close()


def test_guest_storage_keys_observed_in_browser_are_disclosed(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url)
    try:
        page = context.new_page()
        page.goto("/", wait_until="domcontentloaded")
        with page.expect_response("**/api/consent"):
            page.locator('[data-consent-choice="essential_only"]').click()
        page.wait_for_function("Boolean(localStorage.getItem('safeScanConsent'))")
        observed = page.evaluate("({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})")
        observed["cookies"] = [cookie["name"] for cookie in context.cookies()]
        policy = (ROOT / "hackabull/admin_data.py").read_text()
        inventory = (ROOT / "docs/legal/storage-inventory.md").read_text()
        assert observed["local"]
        for names in observed.values():
            assert all(name in policy and name in inventory for name in names), names
    finally:
        context.close()
