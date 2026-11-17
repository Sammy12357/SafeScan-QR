"""Bright QR gradients keep the chosen image colors and readable text copies."""

import base64
import io
import json
import re
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
    with tempfile.TemporaryDirectory(prefix="safescan-bright-gradient-") as temp_dir:
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
    from hackabull.qr_image import (
        qr_ascii_from_payload,
        qr_ascii_motion_frames_from_payload,
        qr_ascii_motion_pngs_from_payload,
    )

    still, animated = qr_ascii_motion_pngs_from_payload(TEST_URL, include_attribution=False)
    with Image.open(io.BytesIO(animated)) as apng:
        gif_frames = []
        for index in range(apng.n_frames):
            apng.seek(index)
            gif_frames.append(apng.convert("RGB"))
    gif = io.BytesIO()
    gif_frames[0].save(gif, format="GIF", save_all=True, append_images=gif_frames[1:], duration=350, loop=0)
    return {
        "still_png_base64": base64.b64encode(still).decode("ascii"),
        "animated_png_base64": base64.b64encode(animated).decode("ascii"),
        "animated_gif_base64": base64.b64encode(gif.getvalue()).decode("ascii"),
        "frame_count": 4,
        "frame_duration_ms": 350,
        "text": qr_ascii_from_payload(TEST_URL, include_attribution=False),
        "ascii_frames": qr_ascii_motion_frames_from_payload(TEST_URL, include_attribution=False),
    }


def set_color(page, selector, value):
    page.locator(selector).evaluate(
        "(input, color) => { input.value = color; input.dispatchEvent(new Event('input', { bubbles: true })); }",
        value,
    )


def color_contrast_on_white(css_rgb):
    rgb = [int(channel) for channel in re.findall(r"\d+", css_rgb)[:3]]
    channels = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in (component / 255 for component in rgb)
    ]
    return 1.05 / (0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2] + 0.05)


def test_bright_pair_saves_as_guest_and_keeps_styled_text_scannable(browser_site, motion_response):
    from hackabull.qr_decode import decode_qr_image

    browser, base_url = browser_site
    context = browser.new_context(
        base_url=base_url,
        viewport={"width": 375, "height": 900},
        permissions=["clipboard-read", "clipboard-write"],
    )
    context.add_init_script(
        "localStorage.setItem('safeScanConsent', JSON.stringify({"
        "consentType: 'essential_only', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()}));"
    )
    page = context.new_page()
    requests = []

    def serve_motion(route):
        requests.append(route.request.post_data_json)
        route.fulfill(
            status=200,
            content_type="application/json",
            headers={"X-SafeScan-Mode": "plain", "X-SafeScan-Verification": "not_checked"},
            body=json.dumps(motion_response),
        )

    page.route("**/api/qr/generate-plain", serve_motion)
    try:
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator('input[name="generateQrMode"][value="plain"]').check()
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('#generateQrSavedStatus').textContent.includes('Browser-only gradients ready')")
        set_color(page, "#generateQrGradientStart", "#f7e9ff")
        set_color(page, "#generateQrGradientEnd", "#ffe6a8")
        assert page.locator("#generateQrGradientSample").get_attribute("data-black-cells") == "true"
        assert "black QR cells" in page.locator("#generateQrGradientHint").inner_text()
        page.locator('[data-gradient-slot-save="1"]').click()
        page.wait_for_function("() => document.querySelector('#generateQrSavedStatus').textContent.includes('Saved Custom gradient 1')")
        assert json.loads(page.evaluate("localStorage.getItem('sqafeQrGradientSlots:guest')")) == {
            "slots": [{"slot": 1, "gradient_start": "#F7E9FF", "gradient_end": "#FFE6A8"}],
        }

        page.reload(wait_until="domcontentloaded")
        page.locator('input[name="generateQrMode"][value="plain"]').check()
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => !document.querySelector('[data-gradient-slot-use=\"1\"]').disabled")
        page.locator('[data-gradient-slot-use="1"]').click()
        assert page.locator("#generateQrGradientStart").input_value().upper() == "#F7E9FF"
        assert page.locator("#generateQrGradientEnd").input_value().upper() == "#FFE6A8"
        page.locator("#generateQrUrlInput").fill(TEST_URL)
        page.locator("#generateQrButton").click()
        page.locator("#generatedMotionTextWrap").wait_for(state="visible", timeout=30_000)
        assert requests == [{
            "url": TEST_URL,
            "format": "ascii_motion",
            "gradient_start": "#F7E9FF",
            "gradient_end": "#FFE6A8",
        }]
        page.locator('input[name="generatedMotionCopyFormat"][value="compact"]').check()
        assert "Bright colors are darkened" in page.locator("#generatedMotionTextDescription").inner_text()
        preview = page.locator("#generatedMotionCompactPreview")
        assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
        colors = preview.locator("span").evaluate_all("elements => elements.map(element => getComputedStyle(element).color)")
        assert color_contrast_on_white(colors[0]) >= 7
        assert color_contrast_on_white(colors[-2]) >= 7
        image = Image.open(io.BytesIO(preview.screenshot())).convert("RGB")
        assert {item.data.decode("utf-8") for item in decode_qr_image(image)} == {TEST_URL}
        page.set_viewport_size({"width": 768, "height": 900})
        page.wait_for_function("() => document.querySelector('#generatedMotionCompactArt').scrollWidth <= document.querySelector('#generatedMotionCompactPreview').clientWidth")
        image = Image.open(io.BytesIO(preview.screenshot())).convert("RGB")
        cv2 = pytest.importorskip("cv2")
        np = pytest.importorskip("numpy")
        decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(np.array(image)[:, :, ::-1])
        assert decoded == TEST_URL

        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        clipboard = page.evaluate("""async () => {
          const item = (await navigator.clipboard.read())[0];
          const plain = await (await item.getType('text/plain')).text();
          const html = await (await item.getType('text/html')).text();
          const doc = new DOMParser().parseFromString(html, 'text/html');
          return {plain, htmlText: doc.querySelector('pre')?.textContent,
            background: doc.querySelector('pre')?.style.background,
            colors: [...doc.querySelectorAll('pre span')].map(span => span.style.color)};
        }""")
        assert clipboard["plain"] == motion_response["text"]
        assert clipboard["htmlText"] == motion_response["text"]
        assert clipboard["background"] == "rgb(255, 255, 255)"
        assert color_contrast_on_white(clipboard["colors"][0]) >= 7
        assert color_contrast_on_white(clipboard["colors"][-2]) >= 7
    finally:
        context.close()


def test_dark_pair_keeps_white_sample(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url)
    page = context.new_page()
    try:
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        assert page.locator("#generateQrGradientSample").get_attribute("data-black-cells") == "false"
        assert "Dark colors" in page.locator("#generateQrGradientHint").inner_text()
    finally:
        context.close()


def test_account_bright_slot_loads_and_mixed_pair_can_be_saved(browser_site):
    browser, base_url = browser_site
    context = browser.new_context(base_url=base_url)
    page = context.new_page()
    writes = []

    def gradients(route):
        if route.request.method == "GET":
            route.fulfill(status=200, content_type="application/json", body=json.dumps({
                "slots": [{"slot": 2, "gradient_start": "#F7E9FF", "gradient_end": "#FFE6A8"}],
            }))
        else:
            writes.append(route.request.post_data_json)
            route.fulfill(status=200, content_type="application/json", body=json.dumps({
                "slot": 1, **writes[-1],
            }))

    try:
        page.route("**/api/qr/gradients**", gradients)
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => !document.querySelector('[data-gradient-slot-use=\"2\"]').disabled")
        page.locator('[data-gradient-slot-use="2"]').click()
        assert page.locator("#generateQrGradientSample").get_attribute("data-black-cells") == "true"
        assert page.locator("#generateQrGradientStart").input_value().upper() == "#F7E9FF"
        set_color(page, "#generateQrGradientStart", "#101820")
        assert page.locator("#generateQrGradientSample").get_attribute("data-black-cells") == "true"
        page.locator('[data-gradient-slot-save="1"]').click()
        page.wait_for_function("() => document.querySelector('#generateQrSavedStatus').textContent.includes('Saved Custom gradient 1')")
        assert writes == [{"gradient_start": "#101820", "gradient_end": "#FFE6A8"}]
        assert page.locator('[data-gradient-slot-use="1"]').is_enabled()
    finally:
        context.close()
