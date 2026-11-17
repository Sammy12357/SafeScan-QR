"""The halftone generator uploads artwork and only exposes verified PNG responses."""

import io
import json
import os
import subprocess
import sys
import tempfile
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest
import qrcode
from PIL import Image

from scripts.ui_screenshots import free_port, isolated_server_env, wait_for_server


ROOT = Path(os.environ.get("SAFESCAN_HALFTONE_TEST_ROOT", Path(__file__).resolve().parents[1])).resolve()
TEST_URL = "https://sqafe.com/learn"


@pytest.fixture(scope="module")
def browser_site():
    playwright_api = pytest.importorskip("playwright.sync_api")
    with tempfile.TemporaryDirectory(prefix="safescan-halftone-ui-") as temp_dir:
        port = free_port()
        base_url = f"http://localhost:{port}"
        server_env = isolated_server_env(temp_dir, base_url)
        server_env["PYTHONPATH"] = str(ROOT)
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
            cwd=ROOT,
            env=server_env,
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
def artwork_png():
    buffer = io.BytesIO()
    Image.new("RGB", (64, 64), "#527b87").save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture(scope="module")
def qr_png():
    buffer = io.BytesIO()
    qrcode.make(TEST_URL).save(buffer, format="PNG")
    return buffer.getvalue()


def new_page(browser, base_url, *, mobile=False):
    context = browser.new_context(
        base_url=base_url,
        viewport={"width": 390 if mobile else 1280, "height": 844 if mobile else 900},
        accept_downloads=True,
    )
    context.add_init_script(
        "localStorage.setItem('safeScanConsent', JSON.stringify({"
        "consentType: 'essential_only', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()}));"
    )
    return context, context.new_page()


def select_halftone(page, artwork_png=None, *, mode="screened"):
    page.goto("/generate-qr", wait_until="domcontentloaded")
    page.locator(f'input[name="generateQrMode"][value="{mode}"]').check()
    page.locator('input[name="generateQrFormat"][value="halftone"]').check()
    assert page.locator("#generateQrHalftoneOptions").is_visible()
    assert page.locator("#generateQrGradientOptions").is_hidden()
    page.locator("#generateQrUrlInput").fill(TEST_URL)
    if artwork_png is not None:
        page.locator("#generateQrHalftoneImage").set_input_files({
            "name": "artwork.png", "mimeType": "image/png", "buffer": artwork_png,
        })
        page.locator("#generateQrHalftonePreview").wait_for(state="visible")
        page.wait_for_function("() => document.querySelector('#generateQrHalftonePreview').naturalWidth > 0")


def multipart_fields(request):
    content_type = request.headers["content-type"]
    assert content_type.startswith("multipart/form-data; boundary=")
    body = request.post_data_buffer
    parsed = BytesParser(policy=policy.default).parsebytes(
        b"MIME-Version: 1.0\r\nContent-Type: " + content_type.encode() + b"\r\n\r\n" + body
    )
    assert parsed.is_multipart()
    return {part.get_param("name", header="content-disposition"): part for part in parsed.iter_parts()}


def assert_request(request, artwork_png, mode):
    assert request.method == "POST"
    assert request.url.endswith("/api/qr/generate-halftone")
    parts = multipart_fields(request)
    assert set(parts) == {"mode", "url", "image"}
    assert parts["mode"].get_content() == mode
    assert parts["url"].get_content() == TEST_URL
    assert parts["image"].get_filename() == "artwork.png"
    assert parts["image"].get_content_type() == "image/png"
    assert parts["image"].get_payload(decode=True) == artwork_png


def test_halftone_requires_an_artwork_file(browser_site):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    requests = []
    page.route("**/api/qr/generate-halftone", lambda route: requests.append(route.request))
    try:
        select_halftone(page)
        page.locator("#generateQrButton").click()
        assert "Choose a PNG, JPEG, or WebP" in page.locator("#generateQrError").inner_text()
        assert page.locator("#generateQrHalftoneImage").evaluate("element => element === document.activeElement")
        assert page.locator("#generatedQrWrap").is_hidden()
        assert requests == []
    finally:
        context.close()


@pytest.mark.parametrize("mode", ["screened", "plain"])
def test_halftone_upload_preview_and_download_require_matching_verification(browser_site, artwork_png, qr_png, mode):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url, mobile=(mode == "plain"))
    requests = []
    response_headers = (
        {"X-SafeScan-Verdict": "safe", "X-SafeScan-Verification": "complete"}
        if mode == "screened" else
        {"X-SafeScan-Mode": "plain", "X-SafeScan-Verification": "not_checked"}
    )

    def serve_qr(route):
        requests.append(route.request)
        route.fulfill(status=200, content_type="image/png", headers=response_headers, body=qr_png)

    page.route("**/api/qr/generate-halftone", serve_qr)
    try:
        select_halftone(page, artwork_png, mode=mode)
        page.locator("#generateQrButton").click()
        page.locator("#generatedQrWrap").wait_for(state="visible")
        assert len(requests) == 1
        assert_request(requests[0], artwork_png, mode)
        assert page.locator("#generatedQrWrap").get_attribute("data-output-format") == "halftone"
        assert page.locator("#generatedQrWrap").get_attribute("data-verification") == (
            "complete" if mode == "screened" else "not_checked"
        )
        assert page.locator("#generatedQrImage").get_attribute("src").startswith("blob:")
        page.wait_for_function("() => document.querySelector('#generatedQrImage').naturalWidth > 0")
        assert "checked for scanning" in page.locator("#generatedQrStatus").inner_text()
        assert page.locator("#generatedQrDownload").get_attribute("download") == (
            "sqafe-halftone-qr.png" if mode == "screened" else "plain-halftone-qr.png"
        )
        with page.expect_download() as download_info:
            page.locator("#generatedQrDownload").click()
        download = download_info.value
        assert download.suggested_filename == (
            "sqafe-halftone-qr.png" if mode == "screened" else "plain-halftone-qr.png"
        )
        assert Path(download.path()).read_bytes() == qr_png
        assert page.locator("#generateQrError").is_hidden()
        if mode == "plain":
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    finally:
        context.close()


def test_halftone_rejects_an_unscannable_artwork_response(browser_site, artwork_png):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    page.route(
        "**/api/qr/generate-halftone",
        lambda route: route.fulfill(
            status=422,
            content_type="application/json",
            body=json.dumps({"code": "qr_generation_unscannable", "detail": "No scannable result"}),
        ),
    )
    try:
        select_halftone(page, artwork_png)
        page.locator("#generateQrButton").click()
        page.locator("#generateQrError").wait_for(state="visible")
        assert "Try a clearer crop or a shorter URL" in page.locator("#generateQrError").inner_text()
        assert page.locator("#generatedQrWrap").is_hidden()
    finally:
        context.close()


@pytest.mark.parametrize("mode", ["screened", "plain"])
def test_halftone_rejects_png_without_required_verification(browser_site, artwork_png, qr_png, mode):
    browser, base_url = browser_site
    context, page = new_page(browser, base_url)
    wrong_headers = (
        {"X-SafeScan-Verdict": "safe", "X-SafeScan-Verification": "incomplete"}
        if mode == "screened" else
        {"X-SafeScan-Mode": "plain", "X-SafeScan-Verification": "not_checked", "X-SafeScan-Verdict": "safe"}
    )
    page.route(
        "**/api/qr/generate-halftone",
        lambda route: route.fulfill(status=200, content_type="image/png", headers=wrong_headers, body=qr_png),
    )
    try:
        select_halftone(page, artwork_png, mode=mode)
        page.locator("#generateQrButton").click()
        page.locator("#generateQrError").wait_for(state="visible")
        assert page.locator("#generatedQrWrap").is_hidden()
        assert page.locator("#generatedQrImage").get_attribute("src") is None
    finally:
        context.close()
