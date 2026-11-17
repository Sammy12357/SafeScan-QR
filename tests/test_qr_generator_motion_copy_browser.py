"""The animated ASCII QR is live text and copies its visible frame."""

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
    from hackabull.qr_image import qr_ascii_motion_frames_from_payload

    return {
        "frame_count": 4,
        "frame_duration_ms": 350,
        "ascii_frames": qr_ascii_motion_frames_from_payload(TEST_URL, include_attribution=False),
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


def decoded_urls(png_bytes):
    from hackabull.qr_decode import decode_qr_image

    with Image.open(io.BytesIO(png_bytes)) as image:
        return {barcode.data.decode("utf-8") for barcode in decode_qr_image(image.convert("RGB"))}


def test_ascii_text_autoplays_without_a_play_button(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        generate_plain_motion(page, motion_response)
        art = page.locator("#generatedMotionTextArt")
        assert page.locator("#generatedMotionToggle").count() == 0
        assert page.locator("#generatedQrImage").is_hidden()
        assert page.locator("#generatedMotionTextWrap img").count() == 0
        assert art.text_content() in motion_response["ascii_frames"]
        assert {"#", "@", "8", "M", "%", "W"}.intersection(art.text_content())
        style = art.evaluate("element => ({font: getComputedStyle(element).fontFamily, size: getComputedStyle(element).fontSize, line: getComputedStyle(element).lineHeight})")
        assert "Sqafe ASCII Mono" in style["font"]
        assert style["size"] == "24px"
        assert style["line"] == "12px"

        observed = {art.text_content()}
        for _ in range(30):
            page.wait_for_timeout(100)
            observed.add(art.text_content())
            if len(observed) == 4:
                break
        assert observed == set(motion_response["ascii_frames"]), "Four ASCII frames did not play automatically"

        page.evaluate("""() => {
          document.querySelector('#generatedMotionTextCopy').addEventListener('click', () => {
            window.__movingFrameAtCopy = document.querySelector('#generatedMotionTextArt').textContent;
          }, { capture: true });
        }""")
        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        assert page.evaluate("navigator.clipboard.readText()") == page.evaluate("window.__movingFrameAtCopy")

        page.evaluate("""() => {
          document.querySelector('#generatedMotionTextDownload').addEventListener('click', () => {
            window.__movingFrameAtDownload = document.querySelector('#generatedMotionTextArt').textContent;
          }, { capture: true });
        }""")
        with page.expect_download() as download_info:
            page.locator("#generatedMotionTextDownload").click()
        assert Path(download_info.value.path()).read_text(encoding="utf-8") == page.evaluate("window.__movingFrameAtDownload")
    finally:
        context.close()


def test_reduced_motion_copy_paste_and_download_preserve_ascii(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    try:
        generate_plain_motion(page, motion_response)
        art = page.locator("#generatedMotionTextArt")
        assert art.text_content() == motion_response["ascii_frames"][0]
        page.wait_for_timeout(750)
        assert art.text_content() == motion_response["ascii_frames"][0]
        assert page.locator("#generatedMotionToggle").count() == 0
        assert page.locator("#generatedQrImage").is_hidden()

        page.evaluate("""() => {
          const button = document.querySelector('#generatedMotionTextCopy');
          button.addEventListener('click', () => {
            window.__asciiAtCopy = document.querySelector('#generatedMotionTextArt').textContent;
          }, { capture: true });
        }""")
        page.locator("#generatedMotionTextCopy").click()
        captured = page.evaluate("window.__asciiAtCopy")
        assert captured == art.text_content()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        assert page.evaluate("navigator.clipboard.readText()") == captured
        assert all(ord(char) < 128 for char in captured)
        assert captured.endswith("\n")
        assert "copied" in page.locator("#generatedMotionTextActionStatus").inner_text().lower()

        clipboard = page.evaluate("""async () => {
          const item = (await navigator.clipboard.read())[0];
          const plain = await (await item.getType('text/plain')).text();
          const html = await (await item.getType('text/html')).text();
          const doc = new DOMParser().parseFromString(html, 'text/html');
          return { types: item.types, plain, htmlText: doc.querySelector('pre')?.textContent,
            style: doc.querySelector('pre')?.getAttribute('style') };
        }""")
        assert "text/plain" in clipboard["types"]
        assert "text/html" in clipboard["types"]
        assert clipboard["plain"] == captured
        assert clipboard["htmlText"] == captured
        assert "line-height: 12px" in clipboard["style"]
        assert "white-space: pre" in clipboard["style"]
        assert "font-weight: 700" in clipboard["style"]

        page.evaluate("""() => {
          const textarea = document.createElement('textarea');
          textarea.id = 'ascii-paste-plain';
          document.body.append(textarea);
          const rich = document.createElement('div');
          rich.id = 'ascii-paste-rich';
          rich.contentEditable = 'true';
          document.body.append(rich);
        }""")
        page.locator("#ascii-paste-plain").focus()
        page.keyboard.press("ControlOrMeta+V")
        assert page.locator("#ascii-paste-plain").input_value() == captured
        page.locator("#ascii-paste-rich").focus()
        page.keyboard.press("ControlOrMeta+V")
        rich_pre = page.locator("#ascii-paste-rich pre")
        assert rich_pre.count() == 1
        assert rich_pre.text_content() == captured
        assert rich_pre.evaluate("element => getComputedStyle(element).whiteSpace") == "pre"
        assert rich_pre.evaluate("element => getComputedStyle(element).lineHeight") == "12px"
        assert rich_pre.evaluate("element => element.clientWidth >= element.scrollWidth")
        assert decoded_urls(rich_pre.screenshot()) == {TEST_URL}
        page.locator("#ascii-paste-rich").evaluate("element => { element.style.width = '375px'; }")
        assert rich_pre.evaluate("element => element.clientWidth >= element.scrollWidth")
        assert decoded_urls(rich_pre.screenshot()) == {TEST_URL}

        with page.expect_download() as download_info:
            page.locator("#generatedMotionTextDownload").click()
        assert Path(download_info.value.path()).read_text(encoding="utf-8") == captured

        page.set_viewport_size({"width": 375, "height": 812})
        page.evaluate("document.fonts.ready")
        paper = page.locator("#generatedMotionTextPaper")
        assert decoded_urls(paper.screenshot()) == {TEST_URL}
    finally:
        context.close()


def test_each_browser_rendered_ascii_frame_decodes_at_mobile_and_tablet(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    try:
        generate_plain_motion(page, motion_response)
        page.evaluate("document.fonts.ready")
        art = page.locator("#generatedMotionTextArt")
        paper = page.locator("#generatedMotionTextPaper")
        for width in (375, 768):
            page.set_viewport_size({"width": width, "height": 900})
            for frame in motion_response["ascii_frames"]:
                art.evaluate("(element, value) => { element.textContent = value; }", frame)
                assert decoded_urls(paper.screenshot()) == {TEST_URL}
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
