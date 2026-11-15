"""Browser errors are pages; API errors retain a stable JSON contract."""

import importlib
import json
import re
import sys

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient


@pytest.fixture()
def error_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'errors.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    yield app, TestClient(app.qr_app, base_url="https://testserver", raise_server_exceptions=False)
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def test_browser_404_has_navigation_no_path_echo_and_request_id(error_app):
    _, client = error_app
    response = client.get("/not-a-page?token=private-secret", headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "We can't find that page" in response.text
    assert "Site navigation" in response.text
    assert "site-footer" in response.text
    assert "private-secret" not in response.text
    assert '<meta name="robots" content="noindex">' in response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert re.fullmatch(r"[A-Z2-7]{4}-[A-Z2-7]{4}", response.headers["X-Request-ID"])
    assert response.headers["X-Request-ID"] in response.text


def test_request_reference_has_eight_base32_characters(error_app):
    errors = importlib.import_module("hackabull.errors")
    references = {errors.new_request_id() for _ in range(32)}
    assert len(references) == 32
    assert all(re.fullmatch(r"[A-Z2-7]{4}-[A-Z2-7]{4}", reference) for reference in references)


def test_api_and_explicit_json_errors_keep_string_error(error_app):
    _, client = error_app
    cases = (
        ("/api/nope", {"Accept": "text/html"}),
        ("/nope", {"Accept": "application/json"}),
        ("/nope", {"X-Requested-With": "fetch"}),
        ("/metrics", {"Accept": "text/html"}),
    )
    for path, headers in cases:
        response = client.get(path, headers=headers)
        assert response.status_code in (403, 404)
        assert response.headers["content-type"].startswith("application/json")
        body = response.json()
        assert isinstance(body["error"], str)
        assert isinstance(body["code"], str)
        assert body["request_id"] == response.headers["X-Request-ID"]
        assert response.headers["Cache-Control"] == "no-store"

    browser = client.get("/nope", headers={"Accept": "application/json;q=0, text/html;q=1"})
    assert browser.headers["content-type"].startswith("text/html")


def test_server_failure_is_generic_and_correlated_in_logs(error_app, caplog):
    app, client = error_app

    @app.qr_app.post("/__error_probe")
    async def fail_probe(request: Request):
        raise RuntimeError("private provider token")

    with caplog.at_level("ERROR", logger="safescan.errors"):
        response = client.post("/__error_probe", data={"secret": "never-log-request-body"}, headers={"Accept": "text/html"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "Something broke on our side" in response.text
    assert "private provider token" not in response.text
    assert "never-log-request-body" not in caplog.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    record = next(json.loads(item.getMessage()) for item in caplog.records if item.name == "safescan.errors")
    assert record["request_id"] == response.headers["X-Request-ID"]
    assert record["route"] == "/__error_probe"


def test_rate_limit_keeps_retry_header_and_browser_countdown(error_app):
    app, client = error_app

    @app.qr_app.get("/__rate_probe")
    async def rate_probe():
        raise HTTPException(status_code=429, headers={"Retry-After": "9"})

    browser = client.get("/__rate_probe", headers={"Accept": "text/html"})
    assert browser.status_code == 429
    assert browser.headers["Retry-After"] == "9"
    assert 'data-retry-countdown>9</span>' in browser.text
    assert "data-retry-button disabled" in browser.text
    api = client.get("/__rate_probe", headers={"Accept": "application/json"})
    assert api.status_code == 429
    assert api.headers["Retry-After"] == "9"
    assert api.json()["retryAfter"] == 9
    assert isinstance(api.json()["error"], str)

    security = importlib.import_module("hackabull.security")

    @app.qr_app.post("/__direct_rate_probe")
    async def direct_rate_probe(request: Request):
        return security.enforce_rate_limit(request, "phase4-direct-probe", 1, 30)

    assert client.post("/__direct_rate_probe").status_code == 200
    direct = client.post("/__direct_rate_probe", headers={"Accept": "text/html"})
    assert direct.status_code == 429
    assert direct.headers["content-type"].startswith("text/html")
    assert 1 <= int(direct.headers["Retry-After"]) <= 30
    assert f'data-retry-countdown>{direct.headers["Retry-After"]}</span>' in direct.text
    assert direct.headers["X-Request-ID"] in direct.text


def test_safe_scan_error_metadata_and_server_detail_redaction(error_app, caplog):
    app, client = error_app
    from hackabull.audit import SafeScanError

    @app.qr_app.get("/api/__coded_error_probe")
    async def coded_error_probe():
        raise SafeScanError("That image is too large.", 413, code="upload_too_large", hint="Choose a smaller image.", field="file")

    coded = client.get("/api/__coded_error_probe")
    assert coded.status_code == 413
    assert coded.json()["error"] == "That image is too large."
    assert coded.json()["code"] == "upload_too_large"
    assert coded.json()["hint"] == "Choose a smaller image."
    assert coded.json()["field"] == "file"

    @app.qr_app.get("/api/__server_error_probe")
    async def server_error_probe():
        raise SafeScanError("ALPHA_SOLANA_RECIPIENT contained a private value", 503)

    with caplog.at_level("ERROR", logger="safescan.errors"):
        server_error = client.get("/api/__server_error_probe")
    assert server_error.status_code == 503
    assert "ALPHA_SOLANA" not in server_error.text
    assert isinstance(server_error.json()["error"], str)
    assert "ALPHA_SOLANA" not in caplog.text
    record = next(json.loads(item.getMessage()) for item in caplog.records if item.name == "safescan.errors")
    assert record["request_id"] == server_error.headers["X-Request-ID"]
    assert record["exception_type"] == "SafeScanError"
    assert "detail" not in record


def test_error_pages_work_when_session_lookup_fails(error_app, monkeypatch):
    _, client = error_app
    app_module = importlib.import_module("hackabull.app_module")

    def broken_session(_request):
        raise RuntimeError("session database unavailable")

    monkeypatch.setattr(app_module, "get_session_user", broken_session)
    response = client.get("/nope", headers={"Accept": "text/html"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "Sign in" in response.text
    assert "session database unavailable" not in response.text
    assert response.headers["X-Request-ID"] in response.text


def test_mobile_scan_fallback_keeps_html_success_and_json_failure(error_app, monkeypatch):
    _, client = error_app
    scanner = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(scanner, "decode_qr_upload", lambda *_args: ("WIFI:T:WPA;S:Test;P:secret;;", None))
    monkeypatch.setattr(scanner, "analyze_qr_payload", lambda payload: {
        "normalized": payload, "status": "CAUTION", "source": "Scanner",
        "score": "0", "threat_class": "N/A", "overallRisk": "caution",
        "verdict": "Review this QR content before using it.",
    })
    success = client.post(
        "/search_qr_api", data={"template_variant": "main_site"},
        files={"file": ("code.png", b"fake-image", "image/png")},
        headers={"Accept": "*/*"},
    )
    assert success.status_code == 200
    assert success.headers["content-type"].startswith("text/html")
    assert "SafeScan QR" in success.text

    failure = client.post("/search_qr_api", data={"capture_source": "invalid"}, headers={"Accept": "*/*"})
    assert failure.status_code == 400
    assert isinstance(failure.json()["error"], str)
    assert failure.json()["request_id"] == failure.headers["X-Request-ID"]

    browser = client.post("/search_qr_api", data={"capture_source": "invalid"}, headers={"Accept": "text/html"})
    assert browser.status_code == 400
    assert browser.headers["content-type"].startswith("text/html")


def test_validation_and_direct_origin_failures_use_error_system(error_app):
    _, client = error_app
    validation = client.post("/legal/data-request", headers={"Accept": "text/html"})
    assert validation.status_code == 400
    assert validation.headers["content-type"].startswith("text/html")
    assert 'id="request-email"' in validation.text
    assert 'aria-invalid="true"' in validation.text
    assert "Enter a valid email address" in validation.text

    origin = client.post("/waitlist", data={"email": "a@example.com"}, headers={"Accept": "text/html", "Origin": "https://untrusted.example"})
    assert origin.status_code == 403
    assert origin.headers["content-type"].startswith("text/html")
    assert origin.headers["X-Request-ID"] in origin.text


def test_data_request_keeps_values_and_does_not_record_invalid_type(error_app):
    app, client = error_app
    response = client.post("/legal/data-request", data={
        "email": "person@example.com", "region": "Ontario",
        "request_type": "unexpected", "details": "Please review this request.",
    })
    assert response.status_code == 400
    assert 'value="person@example.com"' in response.text
    assert 'value="Ontario"' in response.text
    assert "Please review this request." in response.text
    assert "Choose the type of request" in response.text
    with app.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM data_requests").fetchone()[0] == 0


def test_waitlist_error_keeps_email_and_success_uses_redirect(error_app):
    app, client = error_app
    invalid = client.post("/waitlist", data={"email": "not-an-email"})
    assert invalid.status_code == 400
    assert "Join the waitlist" in invalid.text
    assert "not-an-email" in invalid.text
    assert "Enter a valid email address" in invalid.text
    assert invalid.headers["Cache-Control"] == "no-store"
    with app.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM waitlist_signups").fetchone()[0] == 0

    success = client.post("/waitlist", data={"email": "person@example.com"}, follow_redirects=False)
    assert success.status_code == 303
    assert success.headers["location"] == "/waitlist?joined=1"
    joined = client.get(success.headers["location"])
    assert "You're on the list" in joined.text
    assert joined.headers["Cache-Control"] == "no-store"


def test_unexpected_json_fields_do_not_echo_names(error_app):
    _, client = error_app
    response = client.post("/api/analyze", json={
        "url": "https://example.com", "private_token_value": "do-not-show",
    })
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "invalid_request"
    assert "private_token_value" not in response.text
    assert "do-not-show" not in response.text
