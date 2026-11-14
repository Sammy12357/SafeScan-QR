"""Request body and local credential limits added in Phase 5."""

import asyncio
import importlib
import re
import sqlite3
import sys

import httpx
import pytest
from browser_client import BrowserTestClient as TestClient

from hackabull.body_limits import BodySizeLimitMiddleware


def _scope(path, content_type, content_length=None):
    headers = [(b"content-type", content_type.encode("ascii"))]
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
    return {
        "type": "http", "http_version": "1.1", "method": "POST", "path": path,
        "raw_path": path.encode("ascii"), "root_path": "", "scheme": "https",
        "query_string": b"", "headers": headers,
        "client": ("198.51.100.1", 54321), "server": ("testserver", 443),
    }


def _run_limiter(scope, body_messages):
    events = []
    calls = 0
    downstream = []

    async def app(_scope, receive, send):
        downstream.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        nonlocal calls
        message = body_messages[calls]
        calls += 1
        return message

    async def send(message):
        events.append(message)

    asyncio.run(BodySizeLimitMiddleware(app, lambda _request, response: response)(scope, receive, send))
    return events, calls, downstream


def test_declared_oversize_upload_is_rejected_without_reading_a_byte():
    events, reads, downstream = _run_limiter(
        _scope("/api/scan/file", "multipart/form-data; boundary=x", 11 * 1024 * 1024),
        [],
    )
    assert events[0]["status"] == 413
    assert reads == 0
    assert downstream == []


@pytest.mark.parametrize("content_type,limit", [
    ("application/json", 64 * 1024),
    ("application/vnd.safescan+json", 64 * 1024),
    ("application/x-www-form-urlencoded", 16 * 1024),
])
def test_chunked_body_stops_at_first_oversize_chunk(content_type, limit):
    events, reads, downstream = _run_limiter(
        _scope("/api/scan", content_type),
        [
            {"type": "http.request", "body": b"a" * limit, "more_body": True},
            {"type": "http.request", "body": b"b", "more_body": True},
            {"type": "http.request", "body": b"unused", "more_body": False},
        ],
    )
    assert events[0]["status"] == 413
    assert reads == 2
    assert downstream == []


def test_body_within_limit_reaches_parser_unchanged():
    events, reads, downstream = _run_limiter(
        _scope("/api/scan", "application/json"),
        [
            {"type": "http.request", "body": b'{"payload":', "more_body": True},
            {"type": "http.request", "body": b'"safe"}', "more_body": False},
        ],
    )
    assert events[0]["status"] == 200
    assert reads == 2
    assert downstream[0]["body"] == b'{"payload":"safe"}'


@pytest.fixture()
def local_auth_app(tmp_path, monkeypatch):
    db_path = tmp_path / "phase5.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    auth = importlib.import_module("hackabull.routes_scan_auth")
    auth.LOCAL_AUTH_ENABLED = True
    app.RATE_LIMITS.clear()
    yield TestClient(app.qr_app, base_url="https://testserver"), db_path
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def test_local_registration_rejects_long_password_and_email(local_auth_app):
    client, db_path = local_auth_app
    too_long_password = client.post("/auth/register", data={"email": "person@example.com", "password": "x" * 1025})
    assert too_long_password.status_code == 200
    assert "Password is too long" in too_long_password.text
    too_long_email = client.post("/auth/register", data={"email": "a" * 245 + "@example.com", "password": "password123"})
    assert too_long_email.status_code == 200
    assert "Invalid email address" in too_long_email.text
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM local_credentials").fetchone()[0] == 0


def test_integrated_json_and_form_caps_return_413(local_auth_app):
    client, _ = local_auth_app
    json_response = client.post("/api/scan", json={"payload": "x" * (64 * 1024)})
    form_response = client.post("/waitlist", data={"email": "x" * (16 * 1024)})
    assert json_response.status_code == 413
    assert form_response.status_code == 413
    assert json_response.headers["x-content-type-options"] == "nosniff"
    assert form_response.headers["x-content-type-options"] == "nosniff"


def test_chunked_upload_stops_before_receiving_all_eleven_megabytes(local_auth_app):
    client, _ = local_auth_app
    sent_chunks = []

    async def stream():
        for index in range(11):
            sent_chunks.append(index)
            yield b"x" * (1024 * 1024)

    async def upload():
        transport = httpx.ASGITransport(app=client.app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as api:
            return await api.post(
                "/api/scan/file",
                content=stream(),
                headers={"Content-Type": "multipart/form-data; boundary=x"},
            )

    response = asyncio.run(upload())
    assert response.status_code == 413
    assert len(sent_chunks) < 11


def test_password_hash_and_verify_reject_excessive_input_before_pbkdf2(monkeypatch):
    accounts = importlib.import_module("hackabull.accounts")
    monkeypatch.setattr(accounts.hashlib, "pbkdf2_hmac", lambda *_args: pytest.fail("PBKDF2 must not run"))
    with pytest.raises(ValueError):
        accounts.hash_password("x" * 1025)
    assert not accounts.verify_password("x" * 1025, "bad:hash")


def test_local_passwords_do_not_truncate_after_72_bytes():
    accounts = importlib.import_module("hackabull.accounts")
    saved = accounts.hash_password("x" * 72 + "A")
    assert accounts.verify_password("x" * 72 + "A", saved)
    assert not accounts.verify_password("x" * 72 + "B", saved)


def test_capability_ids_use_url_safe_128_bit_random_suffix():
    helpers = importlib.import_module("hackabull.request_helpers")
    ids = {helpers.make_id("report") for _ in range(100)}
    assert len(ids) == 100
    assert all(re.fullmatch(r"report_[A-Za-z0-9_-]{22}", item) for item in ids)
