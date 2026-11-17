"""The animated ASCII QR previews APNG, downloads GIF, and copies text."""

import base64
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from PIL import Image, ImageChops

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
    from hackabull.qr_image import qr_ascii_from_payload, qr_ascii_motion_frames_from_payload, qr_ascii_motion_pngs_from_payload
    from hackabull.qr_motion_gif import qr_ascii_motion_gif_from_apng

    still, animated = qr_ascii_motion_pngs_from_payload(TEST_URL, include_attribution=False)
    gif = qr_ascii_motion_gif_from_apng(animated, TEST_URL)
    return {
        "still_png_base64": base64.b64encode(still).decode("ascii"),
        "animated_png_base64": base64.b64encode(animated).decode("ascii"),
        "animated_gif_base64": base64.b64encode(gif).decode("ascii"),
        "frame_count": 4,
        "frame_duration_ms": 350,
        "text": qr_ascii_from_payload(TEST_URL, include_attribution=False),
        "ascii_frames": qr_ascii_motion_frames_from_payload(TEST_URL, include_attribution=False),
    }


@pytest.fixture(scope="module")
def aurora_motion_response(motion_response):
    from hackabull.qr_image import qr_ascii_motion_pngs_from_payload
    from hackabull.qr_motion_gif import qr_ascii_motion_gif_from_apng

    still, animated = qr_ascii_motion_pngs_from_payload(
        TEST_URL, gradient_start="#153E3E", gradient_end="#4B246B", include_attribution=False,
    )
    return {
        **motion_response,
        "still_png_base64": base64.b64encode(still).decode("ascii"),
        "animated_png_base64": base64.b64encode(animated).decode("ascii"),
        "animated_gif_base64": base64.b64encode(qr_ascii_motion_gif_from_apng(animated, TEST_URL)).decode("ascii"),
    }


@pytest.fixture(scope="module")
def screened_motion_response():
    from hackabull.qr_image import qr_ascii_from_payload, qr_ascii_motion_frames_from_payload, qr_ascii_motion_pngs_from_payload
    from hackabull.qr_motion_gif import qr_ascii_motion_gif_from_apng

    still, animated = qr_ascii_motion_pngs_from_payload(TEST_URL, include_attribution=True)
    gif = qr_ascii_motion_gif_from_apng(animated, TEST_URL)
    return {
        "still_png_base64": base64.b64encode(still).decode("ascii"),
        "animated_png_base64": base64.b64encode(animated).decode("ascii"),
        "animated_gif_base64": base64.b64encode(gif).decode("ascii"),
        "frame_count": 4,
        "frame_duration_ms": 350,
        "text": qr_ascii_from_payload(TEST_URL, include_attribution=True),
        "ascii_frames": qr_ascii_motion_frames_from_payload(TEST_URL, include_attribution=True),
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


def generate_plain_motion(page, motion_response, *, preset="ember"):
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
    if preset != "ember":
        page.locator(f'[data-gradient-preset="{preset}"]').click()
    page.locator("#generateQrUrlInput").fill(TEST_URL)
    page.locator("#generateQrButton").click()
    page.locator("#generatedMotionTextWrap").wait_for(state="visible", timeout=30_000)
    assert requests == [{
        "url": TEST_URL,
        "format": "ascii_motion",
        "gradient_start": "#153E3E" if preset == "aurora" else "#2A1B36",
        "gradient_end": "#4B246B" if preset == "aurora" else "#8A280C",
    }]


def decoded_urls(png_bytes):
    from hackabull.qr_decode import decode_qr_image

    with Image.open(io.BytesIO(png_bytes)) as image:
        return {barcode.data.decode("utf-8") for barcode in decode_qr_image(image.convert("RGB"))}


def test_apng_preview_autoplays_and_copies_stable_ascii(browser_site, motion_response):
    from hackabull.qr_decode import decode_qr_image

    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        generate_plain_motion(page, motion_response)
        preview = page.locator("#generatedQrImage")
        toggle = page.locator("#generatedMotionToggle")
        assert preview.is_visible()
        animated_preview_url = preview.get_attribute("src")
        assert animated_preview_url != page.locator("#generatedMotionAnimatedDownload").get_attribute("href")
        assert page.locator("#generatedMotionAnimatedDownload").inner_text() == "Download animated GIF"
        assert toggle.inner_text() == "Pause motion"
        assert toggle.get_attribute("aria-pressed") == "true"
        assert page.locator("#generatedMotionCompactPreview").is_hidden()
        assert page.locator("#generatedQrWrap pre:visible").count() == 0
        assert page.locator('input[name="generatedMotionCopyFormat"][value="ascii"]').is_checked()
        assert preview.evaluate("element => Math.round(element.getBoundingClientRect().width)") == 480
        page.wait_for_function("() => document.querySelector('#generatedQrImage').complete && document.querySelector('#generatedQrImage').naturalWidth > 0")
        samples = [Image.open(io.BytesIO(preview.screenshot(animations="allow"))).convert("RGB")]
        for _ in range(3):
            page.wait_for_timeout(400)
            samples.append(Image.open(io.BytesIO(preview.screenshot(animations="allow"))).convert("RGB"))
        assert any(ImageChops.difference(samples[0], sample).getbbox() for sample in samples[1:]), "APNG preview did not move"
        assert all(
            {barcode.data.decode("utf-8") for barcode in decode_qr_image(sample)} == {TEST_URL}
            for sample in samples
        )

        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        assert page.evaluate("navigator.clipboard.readText()") == motion_response["ascii_frames"][0]
        with page.expect_download() as download_info:
            page.locator("#generatedMotionTextDownload").click()
        assert Path(download_info.value.path()).read_text(encoding="utf-8") == motion_response["ascii_frames"][0]

        toggle.click()
        assert toggle.inner_text() == "Resume motion"
        assert preview.get_attribute("src") == page.locator("#generatedMotionStillDownload").get_attribute("href")
        paused = preview.screenshot(animations="allow")
        page.wait_for_timeout(400)
        assert preview.screenshot(animations="allow") == paused
        toggle.click()
        assert toggle.inner_text() == "Pause motion"
        assert preview.get_attribute("src") == animated_preview_url
    finally:
        context.close()


def test_downloaded_animated_gif_moves_and_every_frame_scans(browser_site, motion_response):
    from hackabull.qr_decode import decode_qr_image

    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        assert len(json.dumps(motion_response)) < 2_000_000
        generate_plain_motion(page, motion_response)
        with page.expect_download() as download_info:
            page.locator("#generatedMotionAnimatedDownload").click()
        download = download_info.value
        assert download.suggested_filename == "plain-ascii-motion-qr-animated.gif"
        gif_bytes = Path(download.path()).read_bytes()
        assert gif_bytes.startswith(b"GIF89a")
        with Image.open(io.BytesIO(gif_bytes)) as animated:
            assert animated.format == "GIF"
            assert animated.n_frames == 4
            assert animated.info["loop"] == 0
            frames = []
            for index in range(animated.n_frames):
                animated.seek(index)
                assert animated.info["duration"] == 350
                frame = animated.convert("RGB")
                frames.append(frame.copy())
                mobile = frame.resize(
                    (320, round(frame.height * 320 / frame.width)), Image.Resampling.LANCZOS,
                )
                for candidate in (frame, mobile):
                    assert {barcode.data.decode("utf-8") for barcode in decode_qr_image(candidate)} == {TEST_URL}
            assert all(ImageChops.difference(frames[0], frame).getbbox() for frame in frames[1:])
    finally:
        context.close()


def test_reduced_motion_copy_paste_and_download_preserve_ascii(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    try:
        generate_plain_motion(page, motion_response)
        preview = page.locator("#generatedQrImage")
        assert preview.is_visible()
        assert preview.get_attribute("src") == page.locator("#generatedMotionStillDownload").get_attribute("href")
        assert page.locator("#generatedMotionToggle").inner_text() == "Resume motion"
        assert page.locator("#generatedMotionCompactPreview").is_hidden()
        assert page.locator("#generatedQrWrap pre:visible").count() == 0
        first = preview.screenshot(animations="allow")
        page.wait_for_timeout(750)
        assert preview.screenshot(animations="allow") == first

        page.locator("#generatedMotionTextCopy").click()
        captured = motion_response["ascii_frames"][0]
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
        assert clipboard["htmlText"] == captured

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
        raw_text = Path(download_info.value.path()).read_text(encoding="utf-8")
        assert raw_text == captured

        page.set_viewport_size({"width": 375, "height": 812})
        assert preview.evaluate("element => Math.round(element.getBoundingClientRect().width)") == 279
        assert decoded_urls(preview.screenshot(animations="allow")) == {TEST_URL}
        with page.expect_download() as html_download_info:
            page.locator("#generatedMotionHtmlDownload").click()
        with tempfile.TemporaryDirectory(prefix="safescan-ascii-html-") as temp_dir:
            html_path = Path(temp_dir) / html_download_info.value.suggested_filename
            html_download_info.value.save_as(html_path)
            page.goto(html_path.as_uri(), wait_until="domcontentloaded")
            saved_pre = page.locator("pre")
            assert saved_pre.text_content() == captured
            assert saved_pre.evaluate("element => getComputedStyle(element).lineHeight") == "12px"
            assert decoded_urls(saved_pre.screenshot()) == {TEST_URL}
    finally:
        context.close()


def test_compact_unicode_preview_copy_and_styled_html_scan(browser_site, aurora_motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    try:
        generate_plain_motion(page, aurora_motion_response, preset="aurora")
        assert page.locator('input[name="generatedMotionCopyFormat"][value="ascii"]').is_checked()
        page.locator('input[name="generatedMotionCopyFormat"][value="compact"]').check()
        preview = page.locator("#generatedMotionCompactPreview")
        art = page.locator("#generatedMotionCompactArt")
        assert preview.is_visible()
        assert art.text_content() == aurora_motion_response["text"]
        assert "Generated by Sqafe" not in art.text_content()
        assert "Generated by Sqafe" not in aurora_motion_response["ascii_frames"][0]
        assert page.locator("#generatedMotionTextCopy").inner_text() == "Copy compact QR"
        assert len(aurora_motion_response["text"]) < len(aurora_motion_response["ascii_frames"][0]) // 10
        assert art.locator("span").count() == len(aurora_motion_response["text"].split("\n"))
        first_color = art.locator("span").first.evaluate("element => getComputedStyle(element).color")
        last_color = art.locator("span").nth(art.locator("span").count() - 2).evaluate("element => getComputedStyle(element).color")
        assert first_color == "rgb(21, 62, 62)"
        assert last_color == "rgb(75, 36, 107)"
        for width in (375, 768):
            page.set_viewport_size({"width": width, "height": 900})
            assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
            assert decoded_urls(preview.screenshot()) == {TEST_URL}
            assert page.locator("#generatedMotionCompactSizeNotice").is_hidden()

        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        copied = aurora_motion_response["text"]
        assert page.evaluate("navigator.clipboard.readText()") == copied
        assert any(ord(character) > 127 for character in copied)
        clipboard = page.evaluate("""async () => {
          const item = (await navigator.clipboard.read())[0];
          const plain = await (await item.getType('text/plain')).text();
          const html = await (await item.getType('text/html')).text();
          const doc = new DOMParser().parseFromString(html, 'text/html');
          const pre = doc.querySelector('pre');
          return { types: item.types, plain, htmlText: pre?.textContent,
            style: pre?.getAttribute('style'), colors: [...pre.querySelectorAll('span')].map(span => span.style.color) };
        }""")
        assert set(clipboard["types"]) == {"text/plain", "text/html"}
        assert clipboard["plain"] == copied
        assert clipboard["htmlText"] == copied
        assert "line-height: 18px" in clipboard["style"]
        assert clipboard["colors"][0] == "rgb(21, 62, 62)"
        assert clipboard["colors"][-2] == "rgb(75, 36, 107)"

        page.evaluate("""() => {
          const textarea = document.createElement('textarea');
          textarea.id = 'compact-paste-plain';
          textarea.rows = 20;
          textarea.cols = 40;
          document.body.append(textarea);
          const rich = document.createElement('div');
          rich.id = 'compact-paste-rich';
          rich.contentEditable = 'true';
          document.body.append(rich);
        }""")
        page.locator("#compact-paste-plain").focus()
        page.keyboard.press("ControlOrMeta+V")
        assert page.locator("#compact-paste-plain").input_value() == copied
        page.locator("#compact-paste-rich").focus()
        page.keyboard.press("ControlOrMeta+V")
        rich_pre = page.locator("#compact-paste-rich pre")
        assert rich_pre.count() == 1
        assert rich_pre.text_content() == copied
        assert rich_pre.evaluate("element => getComputedStyle(element).lineHeight") == "18px"
        assert rich_pre.evaluate("element => element.clientWidth >= element.scrollWidth")
        assert decoded_urls(rich_pre.screenshot()) == {TEST_URL}

        with page.expect_download() as text_download_info:
            page.locator("#generatedMotionTextDownload").click()
        raw_text = Path(text_download_info.value.path()).read_text(encoding="utf-8")
        assert raw_text == copied
        page.evaluate("value => navigator.clipboard.writeText(value)", raw_text)
        page.locator("#compact-paste-plain").fill("")
        page.locator("#compact-paste-plain").focus()
        page.keyboard.press("ControlOrMeta+V")
        assert page.locator("#compact-paste-plain").input_value() == raw_text
        assert decoded_urls(page.locator("#compact-paste-plain").screenshot()) <= {TEST_URL}
        page.evaluate("""() => {
          const raw = document.createElement('div');
          raw.id = 'compact-paste-raw-rich';
          raw.contentEditable = 'true';
          document.body.append(raw);
        }""")
        page.locator("#compact-paste-raw-rich").focus()
        page.keyboard.press("ControlOrMeta+V")
        assert page.locator("#compact-paste-raw-rich pre").count() == 0
        assert decoded_urls(page.locator("#compact-paste-raw-rich").screenshot()) <= {TEST_URL}

        page.locator('input[name="generatedMotionCopyFormat"][value="ascii"]').check()
        assert preview.is_hidden()
        assert page.locator("#generatedMotionTextCopy").inner_text() == "Copy ASCII QR"
        with page.expect_download() as ascii_download_info:
            page.locator("#generatedMotionTextDownload").click()
        assert Path(ascii_download_info.value.path()).read_text(encoding="utf-8") == aurora_motion_response["ascii_frames"][0]
        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        assert page.evaluate("navigator.clipboard.readText()") == aurora_motion_response["ascii_frames"][0]
        page.locator('input[name="generatedMotionCopyFormat"][value="compact"]').check()
        assert preview.is_visible()
        with page.expect_download() as html_download_info:
            page.locator("#generatedMotionHtmlDownload").click()
        with tempfile.TemporaryDirectory(prefix="safescan-compact-html-") as temp_dir:
            html_path = Path(temp_dir) / html_download_info.value.suggested_filename
            html_download_info.value.save_as(html_path)
            page.goto(html_path.as_uri(), wait_until="domcontentloaded")
            saved_pre = page.locator("pre")
            assert saved_pre.text_content() == copied
            assert saved_pre.evaluate("element => getComputedStyle(element).lineHeight") == "18px"
            assert saved_pre.locator("span").first.evaluate("element => getComputedStyle(element).color") == "rgb(21, 62, 62)"
            assert saved_pre.locator("span").nth(saved_pre.locator("span").count() - 2).evaluate("element => getComputedStyle(element).color") == "rgb(75, 36, 107)"
            assert decoded_urls(saved_pre.screenshot()) == {TEST_URL}
    finally:
        context.close()


def test_apng_scans_at_mobile_and_tablet(browser_site, motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    try:
        generate_plain_motion(page, motion_response)
        preview = page.locator("#generatedQrImage")
        for width in (375, 768):
            page.set_viewport_size({"width": width, "height": 900})
            expected_width = 279 if width == 375 else 480
            assert preview.evaluate("element => Math.round(element.getBoundingClientRect().width)") == expected_width
            for _ in range(3):
                assert decoded_urls(preview.screenshot(animations="allow")) == {TEST_URL}
                page.wait_for_timeout(400)
    finally:
        context.close()


def test_screened_text_exports_keep_attribution(browser_site, screened_motion_response):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, reduced_motion="reduce")
    try:
        page.route("**/api/qr/generate", lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            headers={"X-SafeScan-Verdict": "safe", "X-SafeScan-Verification": "complete"},
            body=json.dumps(screened_motion_response),
        ))
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.locator("#generateQrUrlInput").fill(TEST_URL)
        page.locator("#generateQrButton").click()
        page.locator("#generatedMotionTextWrap").wait_for(state="visible", timeout=30_000)
        assert page.locator("#generatedQrWrap").get_attribute("data-verification") == "complete"
        assert "Generated by Sqafe" in screened_motion_response["text"]
        assert "Generated by Sqafe" in screened_motion_response["ascii_frames"][0]

        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        assert page.evaluate("navigator.clipboard.readText()") == screened_motion_response["ascii_frames"][0]
        page.locator('input[name="generatedMotionCopyFormat"][value="compact"]').check()
        assert page.locator("#generatedMotionCompactArt").text_content() == screened_motion_response["text"]
        page.locator("#generatedMotionTextCopy").click()
        page.wait_for_function("() => document.querySelector('#generatedMotionTextActionStatus').textContent.includes('copied')")
        assert page.evaluate("navigator.clipboard.readText()") == screened_motion_response["text"]
        with page.expect_download() as download_info:
            page.locator("#generatedMotionTextDownload").click()
        assert Path(download_info.value.path()).read_text(encoding="utf-8") == screened_motion_response["text"]
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


def set_gradient_colors(page, start, end):
    for selector, value in (("#generateQrGradientStart", start), ("#generateQrGradientEnd", end)):
        page.locator(selector).evaluate(
            "(input, color) => { input.value = color; input.dispatchEvent(new Event('input', { bubbles: true })); }",
            value,
        )


def test_account_gradient_slots_save_replace_and_refresh(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    slots = {2: {"slot": 2, "gradient_start": "#153E3E", "gradient_end": "#4B246B"}}
    writes = []

    def gradients(route):
        if route.request.method == "GET":
            route.fulfill(status=200, content_type="application/json", body=json.dumps({"slots": list(slots.values())}))
            return
        slot = int(route.request.url.rsplit("/", 1)[-1])
        colors = route.request.post_data_json
        writes.append((slot, colors))
        saved = {"slot": slot, **colors}
        slots[slot] = saved
        route.fulfill(status=200, content_type="application/json", body=json.dumps(saved))

    try:
        page.route("**/api/qr/gradients**", gradients)
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('#generateQrSavedScope').textContent.includes('account')")
        assert page.locator("[data-gradient-slot-use]").count() == 3
        assert page.locator('[data-gradient-slot-use="1"]').is_disabled()
        assert page.locator('[data-gradient-slot-use="2"]').is_enabled()
        page.locator('[data-gradient-slot-use="2"]').click()
        assert page.locator("#generateQrGradientStart").input_value().upper() == "#153E3E"
        assert page.locator("#generateQrGradientEnd").input_value().upper() == "#4B246B"

        set_gradient_colors(page, "#112233", "#334455")
        page.locator('[data-gradient-slot-save="1"]').click()
        page.wait_for_function("() => document.querySelector('#generateQrSavedStatus').textContent.includes('Saved Custom gradient 1')")
        assert writes == [(1, {"gradient_start": "#112233", "gradient_end": "#334455"})]
        assert page.locator('[data-gradient-slot-use="1"]').is_enabled()
        assert page.locator('[data-gradient-slot-save="1"]').inner_text() == "Replace"
        assert page.locator('[data-gradient-slot-use="1"]').get_attribute("aria-pressed") == "true"

        page.locator('[data-gradient-preset="night"]').click()
        page.locator('[data-gradient-slot-use="1"]').click()
        assert page.locator("#generateQrGradientStart").input_value().upper() == "#112233"
        assert page.locator("#generateQrGradientEnd").input_value().upper() == "#334455"
        page.locator('[data-gradient-preset="night"]').click()
        page.locator('[data-gradient-slot-save="1"]').click()
        page.wait_for_function("() => document.querySelector('#generateQrSavedStatus').textContent.includes('Saved Custom gradient 1')")
        assert writes[-1] == (1, {"gradient_start": "#10264A", "gradient_end": "#42316B"})

        # A restored page must discard the previous account's in-memory slots.
        slots.clear()
        slots[3] = {"slot": 3, "gradient_start": "#2A1B36", "gradient_end": "#8A280C"}
        page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))")
        page.wait_for_function("() => document.querySelector('[data-gradient-slot-use=\"3\"]').disabled === false")
        assert page.locator('[data-gradient-slot-use="1"]').is_disabled()
        assert page.locator('[data-gradient-slot-use="3"]').is_enabled()

        # A second visible window can change accounts without hiding this tab.
        slots.clear()
        slots[2] = {"slot": 2, "gradient_start": "#153E3E", "gradient_end": "#4B246B"}
        page.evaluate("window.dispatchEvent(new Event('focus'))")
        page.wait_for_function("() => document.querySelector('[data-gradient-slot-use=\"2\"]').disabled === false")
        assert page.locator('[data-gradient-slot-use="3"]').is_disabled()
    finally:
        context.close()


def test_guest_gradient_slots_are_browser_only_and_never_replace_account_slots(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    state = {"signed_in": False}

    def gradients(route):
        if not state["signed_in"]:
            route.fulfill(status=401, content_type="application/json", body='{"error":"Sign in required"}')
        else:
            route.fulfill(status=200, content_type="application/json", body=json.dumps({
                "slots": [{"slot": 3, "gradient_start": "#10264A", "gradient_end": "#42316B"}],
            }))

    try:
        page.route("**/api/qr/gradients**", gradients)
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.locator("#generateQrUrlInput").fill("https://example.com/private-link")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('#generateQrSavedScope').textContent.includes('browser')")
        page.locator('[data-gradient-slot-save="1"]').click()
        page.wait_for_function("() => document.querySelector('#generateQrSavedStatus').textContent.includes('Saved Custom gradient 1')")
        stored = page.evaluate("localStorage.getItem('sqafeQrGradientSlots:guest')")
        assert json.loads(stored) == {"slots": [{
            "slot": 1, "gradient_start": "#2A1B36", "gradient_end": "#8A280C",
        }]}
        assert "private-link" not in stored

        page.reload(wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('[data-gradient-slot-use=\"1\"]').disabled === false")
        assert page.locator('[data-gradient-slot-use="1"]').is_enabled()

        state["signed_in"] = True
        page.reload(wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('[data-gradient-slot-use=\"3\"]').disabled === false")
        assert page.locator('[data-gradient-slot-use="1"]').is_disabled()
        assert page.locator('[data-gradient-slot-use="3"]').is_enabled()
        assert "account" in page.locator("#generateQrSavedScope").inner_text()

        state["signed_in"] = False
        page.evaluate("localStorage.setItem('sqafeQrGradientSlots:guest', JSON.stringify({slots:[{slot:1,gradient_start:'#FFFFF',gradient_end:'#334455'}]}))")
        page.reload(wait_until="domcontentloaded")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('#generateQrSavedScope').textContent.includes('browser')")
        assert page.locator('[data-gradient-slot-use="1"]').is_disabled()
        assert page.evaluate("localStorage.getItem('sqafeQrGradientSlots:guest')") is None

        page.evaluate("""() => {
          const original = Storage.prototype.setItem;
          Storage.prototype.setItem = function(key, value) {
            if (key === 'sqafeQrGradientSlots:guest') throw new DOMException('Storage full', 'QuotaExceededError');
            return original.call(this, key, value);
          };
        }""")
        page.locator('[data-gradient-slot-save="2"]').click()
        assert "Could not save" in page.locator("#generateQrSavedStatus").inner_text()
        assert page.locator('[data-gradient-slot-use="2"]').is_disabled()
    finally:
        context.close()


def test_gradient_load_failure_never_falls_back_to_guest_storage(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    state = {"status": 500}

    def gradients(route):
        if state["status"] == 500:
            route.fulfill(status=500, content_type="application/json", body='{"error":"Unavailable"}')
        else:
            route.fulfill(status=401, content_type="application/json", body='{"error":"Sign in required"}')

    try:
        page.route("**/api/qr/gradients**", gradients)
        page.goto("/generate-qr", wait_until="domcontentloaded")
        page.evaluate("localStorage.setItem('sqafeQrGradientSlots:guest', JSON.stringify({slots:[{slot:1,gradient_start:'#112233',gradient_end:'#334455'}]}))")
        page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
        page.wait_for_function("() => document.querySelector('#generateQrSavedRetry').classList.contains('hidden') === false")
        assert page.locator('[data-gradient-slot-use="1"]').is_disabled()
        assert page.locator('[data-gradient-slot-save="1"]').is_disabled()
        assert "Could not load" in page.locator("#generateQrSavedStatus").inner_text()
        assert page.locator('[data-gradient-preset="night"]').is_enabled()

        state["status"] = 401
        page.locator("#generateQrSavedRetry").click()
        page.wait_for_function("() => document.querySelector('[data-gradient-slot-use=\"1\"]').disabled === false")
        assert "browser" in page.locator("#generateQrSavedScope").inner_text()
        assert page.locator('[data-gradient-slot-use="1"]').is_enabled()
    finally:
        context.close()
