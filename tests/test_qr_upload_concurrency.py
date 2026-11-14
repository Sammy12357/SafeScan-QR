"""Upload routes keep decode CPU bounded and reject oversized bodies early."""

import asyncio
import importlib
import re
import sys
import threading
import time

import httpx
import pytest


async def browser_post(client, path, *, data=None, files=None):
    page = await client.get("/")
    token = re.search(r'<meta name="csrf-token" content="([a-f0-9]{64})"', page.text)
    assert token
    return await client.post(
        path,
        data={**(data or {}), "csrf_token": token.group(1)},
        files=files,
        headers={"Origin": "https://testserver"},
    )


@pytest.fixture()
def scan_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'upload-concurrency.db').as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    yield app
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def test_both_upload_routes_share_the_decode_concurrency_limit(scan_app, monkeypatch):
    homepage = importlib.import_module("hackabull.routes_scan_auth")
    api = importlib.import_module("hackabull.routes_api")
    guard = threading.Lock()
    active = 0
    peak = 0

    def slow_decode(*_args):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.06)
        with guard:
            active -= 1
        return None, None

    monkeypatch.setattr(homepage, "decode_qr_upload", slow_decode)
    monkeypatch.setattr(api, "decode_qr_upload", slow_decode)

    async def run_requests():
        # Create on this event loop so the semaphore cannot be tied to a
        # TestClient loop from a different test.
        semaphore = asyncio.Semaphore(2)
        monkeypatch.setattr(homepage, "QR_DECODE_SEMAPHORE", semaphore)
        monkeypatch.setattr(api, "QR_DECODE_SEMAPHORE", semaphore)
        first_transport = httpx.ASGITransport(app=scan_app.qr_app, client=("198.51.100.10", 50000))
        second_transport = httpx.ASGITransport(app=scan_app.qr_app, client=("198.51.100.11", 50000))
        async with httpx.AsyncClient(transport=first_transport, base_url="https://testserver") as first, \
                httpx.AsyncClient(transport=second_transport, base_url="https://testserver") as second:
            for client, email in ((first, "first@example.com"), (second, "second@example.com")):
                account = await browser_post(client, "/auth/register", data={"email": email, "password": "password123"})
                assert account.status_code in (200, 303)
            requests = [
                browser_post(client, "/search_qr_api", files={"file": ("frame.png", b"x", "image/png")})
                for client in (first, second)
            ] + [
                browser_post(client, "/api/scan/file", files={"file": ("frame.png", b"x", "image/png")})
                for client in (first, second)
            ]
            return await asyncio.gather(*requests)

    responses = asyncio.run(run_requests())
    assert [response.status_code for response in responses] == [200, 200, 400, 400]
    assert peak == 2


def test_both_upload_routes_bound_read_size_before_decoding(scan_app, monkeypatch):
    homepage = importlib.import_module("hackabull.routes_scan_auth")
    api = importlib.import_module("hackabull.routes_api")
    monkeypatch.setattr(homepage, "MAX_QR_UPLOAD_BYTES", 16)
    monkeypatch.setattr(api, "MAX_QR_UPLOAD_BYTES", 16)
    monkeypatch.setattr(homepage, "decode_qr_upload", lambda *_args: pytest.fail("oversize homepage file decoded"))
    monkeypatch.setattr(api, "decode_qr_upload", lambda *_args: pytest.fail("oversize API file decoded"))

    async def run_requests():
        transport = httpx.ASGITransport(app=scan_app.qr_app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            account = await browser_post(client, "/auth/register", data={"email": "scanner@example.com", "password": "password123"})
            assert account.status_code in (200, 303)
            file = {"file": ("too-large.png", b"x" * 17, "image/png")}
            home = await browser_post(client, "/search_qr_api", files=file)
            mobile = await browser_post(client, "/api/scan/file", files=file)
            return home, mobile

    home, mobile = asyncio.run(run_requests())
    assert home.status_code == 200 and "too large" in home.text.lower()
    assert mobile.status_code == 400 and "too large" in mobile.text.lower()
