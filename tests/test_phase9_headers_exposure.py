"""Public exposure checks for Phase 9 headers, probes, and metadata."""

import importlib
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def site(tmp_path, monkeypatch):
    def load(*, production=False):
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'phase9.db').as_posix()}")
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setenv("APP_URL", "https://testserver")
        monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
        monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://trusted.example")
        monkeypatch.setenv("MOCK_MODE", "true")
        monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
        monkeypatch.setenv("PRIVACY_HASH_SALT", "Phase9Test_48a35c1b70e9f2d684ac0759")
        if production:
            monkeypatch.setenv("RENDER", "true")
        else:
            monkeypatch.delenv("RENDER", raising=False)
        for name in tuple(sys.modules):
            if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
                sys.modules.pop(name, None)
        app = importlib.import_module("hackabull")
        return app, TestClient(app.qr_app, base_url="https://testserver")

    yield load
    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def test_production_disables_openapi_and_docs_but_keeps_public_routes(site):
    _, client = site(production=True)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/health").json() == {"status": "ok"}


def test_development_keeps_openapi_and_docs(site):
    _, client = site()
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_probe_errors_hide_backend_details(site, monkeypatch):
    _, client = site()
    module = importlib.import_module("hackabull.app_module")

    def fail():
        raise RuntimeError("private database path and credential")

    monkeypatch.setattr(module, "database_path", fail)
    ready = client.get("/health/ready")
    assert ready.status_code == 503
    assert ready.json() == {"status": "not_ready"}
    assert "private" not in ready.text

    monkeypatch.setattr(module, "reputation_configuration", fail)
    providers = client.get("/health/providers")
    assert providers.status_code == 503
    assert providers.json() == {"status": "unavailable"}
    assert "credential" not in providers.text


def test_security_headers_keep_scanner_and_login_features(site):
    _, client = site()
    home = client.get("/")
    test_site = client.get("/test-site")
    login = client.get("/login")
    status = client.get("/health")
    static = client.get("/static/qr-camera.js")
    missing = client.get("/not-a-route")

    assert home.status_code == 200
    assert test_site.status_code == 200
    assert login.status_code == 200
    assert home.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert test_site.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert login.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    for response in (status, static, missing):
        assert response.headers["cross-origin-opener-policy"] == "same-origin"
    for response in (home, status, static, missing):
        assert response.headers["cross-origin-resource-policy"] == "same-origin"
        assert response.headers["x-permitted-cross-domain-policies"] == "none"
        assert response.headers["x-content-type-options"] == "nosniff"
        policy = response.headers["permissions-policy"]
        assert "camera=(self)" in policy
        assert "clipboard-write=(self)" in policy
        for blocked in ("microphone", "geolocation", "usb", "bluetooth", "browsing-topics"):
            assert f"{blocked}=()" in policy


def test_probe_cookie_cors_and_static_directory_regressions(site):
    _, client = site()
    for path in (
        "/health", "/health/live", "/health/ready", "/health/providers",
        "/api/health", "/.well-known/security.txt",
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert "set-cookie" not in response.headers

    login = client.get("/login")
    assert login.status_code == 200
    assert "Secure" in login.headers["set-cookie"]
    assert "HttpOnly" in login.headers["set-cookie"]

    allowed = client.options(
        "/api/app-runtime",
        headers={"Origin": "https://trusted.example", "Access-Control-Request-Method": "GET"},
    )
    denied = client.options(
        "/api/app-runtime",
        headers={"Origin": "https://not-trusted.example", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://trusted.example"
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert allowed.headers["cross-origin-resource-policy"] == "same-origin"
    assert "access-control-allow-origin" not in denied.headers

    for path in ("/static/", "/static/vendor/", "/static/vendor/zxing-wasm/"):
        response = client.get(path)
        assert response.status_code in (403, 404)
        assert "Directory listing" not in response.text
    asset = client.get("/static/qr-camera.js")
    assert asset.status_code == 200
    assert "immutable" in asset.headers["cache-control"]


def test_security_txt_is_public_plain_text_and_current(site):
    _, client = site()
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "Contact: mailto:safescanqr@gmail.com" in response.text
    assert "Preferred-Languages: en" in response.text
    assert "Canonical:" not in response.text  # same file is served on both public hosts
    expiry = next(line.split(": ", 1)[1] for line in response.text.splitlines() if line.startswith("Expires: "))
    expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    assert now < expires_at < now + timedelta(days=366)
    assert response.headers["cache-control"] == "public, max-age=86400"
