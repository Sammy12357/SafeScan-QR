"""The browser gate must observe an attempt even when routing aborts it."""

import os

import pytest

from scripts.legal_network_gate import first_party_request, record_attempt, unexpected_request


BASE_URL = "http://localhost:9000"


def test_exact_first_party_origin_and_login_only_google_exception():
    assert first_party_request("http://localhost:9000/static/app.js", BASE_URL)
    assert not first_party_request("http://localhost:9000@evil.example/static/app.js", BASE_URL)
    assert unexpected_request("http://localhost:9000@evil.example/static/app.js", BASE_URL, "/", "script") == "http://evil.example"
    assert unexpected_request("https://accounts.google.com/gsi/client", BASE_URL, "/login", "script") is None
    assert unexpected_request("https://accounts.google.com/gsi/client", BASE_URL, "/", "script") == "https://accounts.google.com"
    assert unexpected_request("https://accounts.google.com/gsi/client", BASE_URL, "/login", "image") == "https://accounts.google.com"
    assert unexpected_request("https://accounts.google.com/gsi/other", BASE_URL, "/login", "script") == "https://accounts.google.com"
    assert unexpected_request("https://accounts.google.com/gsi/client?token=private", BASE_URL, "/login", "script") == "https://accounts.google.com"
    assert first_party_request("ws://localhost:9000/events", BASE_URL)
    assert unexpected_request("wss://tracker.example.test/socket?secret=private", BASE_URL, "/", "websocket") == "wss://tracker.example.test"
    assert unexpected_request("data:image/png;base64,a", BASE_URL, "/", "image") is None


def test_real_browser_records_injected_external_image_before_aborting_it():
    playwright_api = pytest.importorskip("playwright.sync_api")
    with playwright_api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=True)
        except playwright_api.Error as exc:
            if os.environ.get("SAFESCAN_REQUIRE_BROWSER") == "1":
                raise
            pytest.skip(f"Chromium unavailable for browser check: {exc}")
        try:
            context = browser.new_context()
            try:
                attempts = []
                context.on("request", lambda request: record_attempt(request.url, request.resource_type,
                           BASE_URL, "injected", "/", "dark", attempts))
                context.route("**/*", lambda route: route.abort())
                def block_websocket(route):
                    record_attempt(route.url, "websocket", BASE_URL, "injected", "/", "dark", attempts)
                    route.close()
                context.route_web_socket("**/*", block_websocket)
                page = context.new_page()
                page.set_content('''<img src="https://tracker.example.test/pixel?secret=never-log-this">
                    <script>new WebSocket('wss://tracker.example.test/socket?secret=never-log-this')</script>''',
                    wait_until="networkidle")
                assert {attempt["destination"] for attempt in attempts} == {
                    "https://tracker.example.test", "wss://tracker.example.test"}
                assert {attempt["resource_type"] for attempt in attempts} == {"image", "websocket"}
                assert "never-log-this" not in repr(attempts)
            finally:
                context.close()
        finally:
            browser.close()
