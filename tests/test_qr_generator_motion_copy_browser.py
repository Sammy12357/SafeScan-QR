"""The ASCII motion preview plays, while its text snapshot copies as text."""

import base64
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from PIL import Image

from scripts.ui_screenshots import free_port, isolated_server_env, wait_for_server


ROOT = Path(__file__).resolve().parents[1]
TEST_URL = "https://sqafe.com/"


@pytest.fixture(scope="module")
def browser_site():
    playwright_api = pytest.importorskip("playwright.sync_api")
    with tempfile.TemporaryDirectory(prefix="safescan-motion-copy-") as temp_dir:
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


@pytest.fixture(scope="module")
def motion_response():
    from hackabull.qr_image import qr_ascii_from_payload

    text = qr_ascii_from_payload(TEST_URL, ec="H", include_attribution=False)
    frames = [Image.new("RGB", (64, 64), color) for color in ("#b51f42", "#1f55b5", "#26a674", "#a7691c")]
    still = io.BytesIO()
    frames[0].save(still, format="PNG")
    animated = io.BytesIO()
    frames[0].save(animated, format="PNG", save_all=True, append_images=frames[1:], duration=350, loop=0)
    return {
        "still_png_base64": base64.b64encode(still.getvalue()).decode("ascii"),
        "animated_png_base64": base64.b64encode(animated.getvalue()).decode("ascii"),
        "frame_count": 4,
        "frame_duration_ms": 350,
        "text": text,
    }


def new_page(browser, base_url, *, reduced_motion="no-preference"):
    context = browser.new_context(
        base_url=base_url,
        viewport={"width": 1440, "height": 900},
        reduced_motion=reduced_motion,
        permissions=["clipboard-read", "clipboard-write"],
    )
    page = context.new_page()
    page.add_init_script(
        "localStorage.setItem('safeScanConsent', JSON.stringify({"
        "consentType: 'essential_only', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()}));"
    )
    return context, page


def generate_plain_motion(page, motion_response):
    requests = []

    def serve_motion(route):
        requests.append(json.loads(route.request.post_data))
        route.fulfill(
            status=200,
            content_type="application/json",
            headers={"X-SafeScan-Mode": "plain", "X-SafeScan-Verification": "not_checked"},
            body=json.dumps(motion_response),
        )

    page.route("**/api/qr/generate-plain", serve_motion)
    page.goto("/generate-qr", wait_until="domcontentloaded")
    page.locator('input[name="generateQrMode"][value="plain"]').check()
    page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
    page.locator("#generateQrUrlInput").fill(TEST_URL)
    page.locator("#generateQrButton").click()
    page.locator("#generatedMotionTextWrap").wait_for(state="visible", timeout=30_000)
    assert requests == [{
        "url": TEST_URL,
        "format": "ascii_motion",
        "gradient_start": "#2A1B36",
        "gradient_end": "#8A280C",
    }]


def image_pixel(page):
    screenshot = page.locator("#generatedQrImage").screenshot(animations="allow")
    with Image.open(io.BytesIO(screenshot)) as frame:
        return frame.convert("RGB").getpixel((frame.width // 2, frame.height // 2))


def test_motion_autoplays_and_text_snapshot_copies(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        generate_plain_motion(page, motion_response)
        toggle = page.locator("#generatedMotionToggle")
        assert toggle.inner_text() == "Pause motion"
        assert toggle.get_attribute("aria-pressed") == "true"
        assert page.locator("#generatedQrImage").get_attribute("src") == page.locator("#generatedMotionAnimatedDownload").get_attribute("href")

        page.locator("#generatedQrImage").scroll_into_view_if_needed()
        page.wait_for_function("() => document.querySelector('#generatedQrImage').complete && document.querySelector('#generatedQrImage').naturalWidth > 0")
        first_pixel = image_pixel(page)
        colors = {(181, 31, 66), (31, 85, 181), (38, 166, 116), (167, 105, 28)}
        assert first_pixel in colors
        changed = False
        for _ in range(12):
            page.wait_for_timeout(200)
            next_pixel = image_pixel(page)
            if next_pixel in colors and next_pixel != first_pixel:
                changed = True
                break
        assert changed, "Animated PNG preview did not advance frames"

        art = page.locator("#generatedMotionTextArt")
        assert art.text_content() == motion_response["text"]
        assert {"▀", "▄", "█"}.intersection(art.text_content())
        assert page.locator("#generatedMotionTextWrap img").count() == 0
        page.locator("#generatedMotionTextCopy").click()
        assert page.evaluate("navigator.clipboard.readText()") == art.text_content()
        assert "copied" in page.locator("#generatedMotionTextActionStatus").inner_text().lower()

        with page.expect_download() as download_info:
            page.locator("#generatedMotionTextDownload").click()
        assert Path(download_info.value.path()).read_text(encoding="utf-8") == art.text_content()
    finally:
        context.close()


def test_reduced_motion_stays_still_until_play(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    try:
        generate_plain_motion(page, motion_response)
        toggle = page.locator("#generatedMotionToggle")
        assert toggle.inner_text() == "Play motion"
        assert toggle.get_attribute("aria-pressed") == "false"
        assert page.locator("#generatedQrImage").get_attribute("src") == page.locator("#generatedMotionStillDownload").get_attribute("href")

        toggle.click()
        assert toggle.inner_text() == "Pause motion"
        assert toggle.get_attribute("aria-pressed") == "true"
        assert page.locator("#generatedQrImage").get_attribute("src") == page.locator("#generatedMotionAnimatedDownload").get_attribute("href")
    finally:
        context.close()


def test_existing_text_qr_still_fits_and_copies(browser_site):
    from hackabull.qr_image import qr_ascii_from_payload

    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    page.set_viewport_size({"width": 375, "height": 812})
    frames = [
        qr_ascii_from_payload(TEST_URL, mask_pattern=mask, include_attribution=False)
        for mask in range(4)
    ]
    requests = []

    def serve_text(route):
        requests.append(json.loads(route.request.post_data))
        route.fulfill(
            status=200,
            content_type="application/json",
            headers={"X-SafeScan-Mode": "plain", "X-SafeScan-Verification": "not_checked"},
            body=json.dumps({"text": frames[0], "frames": frames}),
        )

    try:
        page.route("**/api/qr/generate-plain", serve_text)
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator('input[name="generateQrMode"][value="plain"]').check()
        page.locator('input[name="generateQrFormat"][value="ascii"]').check()
        page.locator("#generateQrUrlInput").fill(TEST_URL)
        page.locator("#generateQrButton").click()
        page.locator("#generatedAsciiWrap").wait_for(state="visible", timeout=30_000)
        assert requests == [{"url": TEST_URL, "format": "ascii", "animation": True}]
        assert page.locator("#generatedMotionTextWrap").is_hidden()

        # Freeze the first frame while checking what Copy text places on the clipboard.
        page.locator("#generatedAsciiMotionToggle").click()
        art = page.locator("#generatedAsciiArt")
        assert art.text_content() == frames[0]
        fit = page.locator("#generatedAsciiWrap .generated-ascii-paper").evaluate(
            """paper => {
                const art = paper.querySelector('pre');
                const style = getComputedStyle(paper);
                const available = paper.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
                return { available, rendered: art.scrollWidth };
            }"""
        )
        assert fit["rendered"] <= fit["available"] + 1
        assert page.locator("#generatedAsciiSizeNotice").is_hidden()

        page.locator("#generatedAsciiCopy").click()
        assert page.evaluate("navigator.clipboard.readText()") == art.text_content()
        assert "copied" in page.locator("#generatedAsciiActionStatus").inner_text().lower()
    finally:
        context.close()
