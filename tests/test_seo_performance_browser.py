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


def test_model_is_deferred_until_pointer_intent_and_scanner_still_works(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    requests = model_requests(page)
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
    try:
        page.goto("/", wait_until="domcontentloaded")
        page.wait_for_load_state("networkidle")
        assert page.locator(".spline-showcase").evaluate("node => node.classList.contains('webgl-fallback')")
        assert not THREE_ASSETS.intersection(requests)

        page.locator("#modelActivation").hover()
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


def test_reduced_motion_keeps_static_model(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    requests = model_requests(page)
    try:
        page.goto("/", wait_until="networkidle")
        assert page.locator("#modelActivation").is_hidden()
        assert page.locator(".spline-showcase.webgl-fallback").count() == 1
        assert not THREE_ASSETS.intersection(requests)
    finally:
        context.close()


def test_mobile_scanner_works_without_loading_model(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    page.set_viewport_size({"width": 375, "height": 812})
    requests = model_requests(page)
    try:
        page.goto("/", wait_until="networkidle")
        page.locator("#urlInput").fill("WIFI:T:WPA;S:Mobile;P:test;;")
        page.get_by_role("button", name="Analyze Payload").click()
        page.locator("#riskVerdictModal").wait_for(timeout=20_000)
        assert "WIFI:T:WPA;S:Mobile;P:test;;" in page.locator(".decoded-payload").first.inner_text()
        assert not THREE_ASSETS.intersection(requests)
    finally:
        context.close()
