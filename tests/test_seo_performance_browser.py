"""The optional hero model must not delay the scanner's first load."""

import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import pytest

from scripts.ui_screenshots import free_port, isolated_server_env, wait_for_server


ROOT = Path(__file__).resolve().parents[1]
THREE_ASSETS = {"safescan-3d.js", "three.module.js"}


@pytest.fixture(scope="module")
def browser_site():
    playwright_api = pytest.importorskip("playwright.sync_api")
    with tempfile.TemporaryDirectory(prefix="safescan-seo-performance-") as temp_dir:
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


def new_page(browser, base_url, *, reduced_motion="no-preference"):
    context = browser.new_context(
        base_url=base_url,
        viewport={"width": 1440, "height": 900},
        reduced_motion=reduced_motion,
    )
    page = context.new_page()
    page.add_init_script(
        "localStorage.setItem('safeScanConsent', JSON.stringify({"
        "consentType: 'essential_only', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()}));"
    )
    return context, page


def model_requests(page):
    requests = []
    page.on("request", lambda request: requests.append(urlparse(request.url).path.rsplit("/", 1)[-1]))
    return requests


def test_visible_model_starts_automatically_and_scanner_still_works(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    requests = model_requests(page)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
    try:
        page.goto("/", wait_until="domcontentloaded")
        assert page.locator("#urlInput").is_visible()
        page.wait_for_load_state("networkidle")
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert THREE_ASSETS.issubset(requests)
        assert page.locator("#modelActivation").is_hidden()

        page.locator("#urlInput").fill("WIFI:T:WPA;S:Test;P:test;;")
        page.get_by_role("button", name="Analyze Payload").click()
        page.locator("#riskVerdictModal").wait_for(timeout=20_000)
        assert "WIFI:T:WPA;S:Test;P:test;;" in page.locator(".decoded-payload").first.inner_text()
        assert errors == []
    finally:
        context.close()


def test_model_can_be_activated_with_keyboard(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        page.add_init_script("window.IntersectionObserver = class { observe() {} disconnect() {} };")
        page.goto("/", wait_until="networkidle")
        button = page.locator("#modelActivation")
        button.focus()
        assert button.evaluate("node => document.activeElement === node")
        page.keyboard.press("Enter")
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert page.locator("#safeScanModel").evaluate("node => document.activeElement === node")
        page.keyboard.press("ArrowRight")
        assert page.locator("#safeScanModel").evaluate("node => document.activeElement === node")
    finally:
        context.close()


def test_auto_start_preserves_focus_on_the_model(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        page.add_init_script(
            "window.IntersectionObserver = class {"
            "constructor(callback) { window.modelVisible = callback; }"
            "observe() {} disconnect() {} };"
        )
        page.goto("/", wait_until="networkidle")
        page.locator("#modelActivation").focus()
        page.evaluate("window.modelVisible([{ isIntersecting: true }])")
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert page.locator("#safeScanModel").evaluate("node => document.activeElement === node")
    finally:
        context.close()


def test_failed_model_load_can_be_retried(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    blocked = False

    def fail_first_model_request(route):
        nonlocal blocked
        if not blocked:
            blocked = True
            route.abort()
        else:
            route.continue_()

    page.route("**/static/safescan-3d.js?*", fail_first_model_request)
    try:
        page.goto("/", wait_until="networkidle")
        retry = page.get_by_role("button", name="Retry 3D model")
        retry.wait_for(timeout=20_000)
        assert retry.is_visible()
        retry.click()
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert retry.is_hidden()
    finally:
        context.close()


def test_failed_three_dependency_can_be_retried(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    blocked = False

    def fail_first_three_request(route):
        nonlocal blocked
        if not blocked:
            blocked = True
            route.abort()
        else:
            route.continue_()

    page.route("**/static/vendor/three.module.js?*", fail_first_three_request)
    try:
        page.goto("/", wait_until="networkidle")
        retry = page.get_by_role("button", name="Retry 3D model")
        retry.wait_for(timeout=20_000)
        retry.click()
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert retry.is_hidden()
    finally:
        context.close()


def test_late_webgl_context_loss_exposes_retry_and_recovers(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        page.goto("/", wait_until="networkidle")
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert page.locator("#modelActivation").is_hidden()
        page.locator("#safeScanModel").focus()

        has_extension = page.evaluate(
            """() => {
                const canvas = document.querySelector('#safeScanModel');
                const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
                const extension = gl?.getExtension('WEBGL_lose_context');
                if (!extension) return false;
                extension.loseContext();
                return true;
            }"""
        )
        if not has_extension:
            pytest.skip("WEBGL_lose_context unavailable in this Chromium build")

        page.locator('.spline-showcase.webgl-fallback[data-webgl-fallback-reason="context-lost"]').wait_for(
            timeout=20_000
        )
        retry = page.get_by_role("button", name="Retry 3D model")
        retry.wait_for(timeout=20_000)
        assert retry.is_visible()
        assert retry.evaluate("node => document.activeElement === node")
        retry.click()
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert retry.is_hidden()
    finally:
        context.close()


def test_reduced_motion_keeps_static_model_until_manual_play(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    requests = model_requests(page)
    try:
        page.goto("/", wait_until="networkidle")
        play = page.get_by_role("button", name="Play 3D model")
        assert play.is_visible()
        assert page.locator(".spline-showcase.webgl-fallback").count() == 1
        assert not THREE_ASSETS.intersection(requests)
        play.click()
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert THREE_ASSETS.issubset(requests)
        assert play.is_hidden()
    finally:
        context.close()


def test_mobile_model_starts_when_scrolled_into_view(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    page.set_viewport_size({"width": 375, "height": 812})
    requests = model_requests(page)
    try:
        page.goto("/", wait_until="networkidle")
        assert not THREE_ASSETS.intersection(requests)
        page.locator(".spline-showcase").scroll_into_view_if_needed()
        page.locator(".spline-showcase.webgl-ready").wait_for(timeout=20_000)
        assert THREE_ASSETS.issubset(requests)
        page.locator("#urlInput").fill("WIFI:T:WPA;S:Mobile;P:test;;")
        page.get_by_role("button", name="Analyze Payload").click()
        page.locator("#riskVerdictModal").wait_for(timeout=20_000)
        assert "WIFI:T:WPA;S:Mobile;P:test;;" in page.locator(".decoded-payload").first.inner_text()
    finally:
        context.close()
