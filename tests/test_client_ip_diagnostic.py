"""The temporary ingress probe is gated and never returns raw IP values."""

import importlib
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request


@pytest.fixture()
def diagnostic_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'client-ip-diag.db'}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes_admin = importlib.import_module("hackabull.routes_admin")
    diagnostic = importlib.import_module("hackabull.ip_diagnostic")
    app.RATE_LIMITS.clear()
    yield app, routes_admin, diagnostic
    app.RATE_LIMITS.clear()
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def make_request(headers=()):
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/admin/debug/client-ip",
        "raw_path": b"/admin/debug/client-ip",
        "query_string": b"",
        "headers": [(name.lower().encode(), value.encode()) for name, value in headers],
        "client": ("198.51.100.9", 50000),
        "server": ("testserver", 443),
    })


def test_probe_requires_render_opt_in_and_strong_key(monkeypatch, diagnostic_app):
    app, _, _ = diagnostic_app
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("CLIENT_IP_DIAGNOSTIC_ENABLED", raising=False)
    monkeypatch.delenv("CLIENT_IP_DIAGNOSTIC_HMAC_KEY", raising=False)
    client = TestClient(app.qr_app, base_url="https://testserver")
    assert client.get("/admin/debug/client-ip").status_code == 404

    monkeypatch.setenv("CLIENT_IP_DIAGNOSTIC_ENABLED", "true")
    monkeypatch.setenv("CLIENT_IP_DIAGNOSTIC_HMAC_KEY", "too-short")
    assert client.get("/admin/debug/client-ip").status_code == 404

    monkeypatch.setenv("CLIENT_IP_DIAGNOSTIC_HMAC_KEY", "a" * 32)
    monkeypatch.delenv("RENDER", raising=False)
    assert client.get("/admin/debug/client-ip").status_code == 404
    monkeypatch.setenv("RENDER", "true")
    assert client.get("/admin/debug/client-ip").status_code == 401


def test_owner_probe_returns_only_stable_fingerprints(monkeypatch, diagnostic_app):
    app, routes_admin, _ = diagnostic_app
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("CLIENT_IP_DIAGNOSTIC_ENABLED", "true")
    monkeypatch.setenv("CLIENT_IP_DIAGNOSTIC_HMAC_KEY", "b" * 32)
    def allow_owner(_request, role):
        assert role == "owner"
        return {"role": "owner"}

    monkeypatch.setattr(routes_admin, "require_role_user", allow_owner)
    client = TestClient(app.qr_app, base_url="https://testserver", client=("198.51.100.9", 50000))

    first = client.get("/admin/debug/client-ip", headers={
        "CF-Connecting-IP": "203.0.113.10",
        "X-Forwarded-For": "192.0.2.1",
    })
    second = client.get("/admin/debug/client-ip", headers={
        "CF-Connecting-IP": "203.0.113.10",
        "X-Forwarded-For": "192.0.2.2",
    })

    assert first.status_code == second.status_code == 200
    assert first.headers["Cache-Control"] == "no-store"
    assert set(first.json()) == {
        "edgeHeaderPresent", "edgeHeaderSingle", "edgeHeaderValid", "resolvedIpValid",
        "edgeFingerprint", "resolvedFingerprint", "fingerprintsMatch",
    }
    assert first.json()["edgeFingerprint"] == second.json()["edgeFingerprint"]
    assert first.json()["resolvedFingerprint"] != second.json()["resolvedFingerprint"]
    assert len(first.json()["edgeFingerprint"]) == 32
    assert first.json()["fingerprintsMatch"] is False
    for raw_value in ("203.0.113.10", "192.0.2.1", "192.0.2.2", "198.51.100.9"):
        assert raw_value not in first.text
        assert raw_value not in second.text


def test_probe_marks_duplicate_or_invalid_edge_headers_without_hashing_them(diagnostic_app):
    _, _, diagnostic = diagnostic_app
    request = make_request([
        ("CF-Connecting-IP", "203.0.113.10"),
        ("CF-Connecting-IP", "192.0.2.2"),
    ])
    snapshot = diagnostic.diagnostic_snapshot(request, "127.0.0.1", "c" * 32)
    assert snapshot["edgeHeaderPresent"] is True
    assert snapshot["edgeHeaderSingle"] is False
    assert snapshot["edgeHeaderValid"] is False
    assert snapshot["edgeFingerprint"] is None
    assert snapshot["resolvedIpValid"] is True

    invalid = diagnostic.diagnostic_snapshot(
        make_request([("CF-Connecting-IP", "203.0.113.10, 192.0.2.2")]),
        "127.0.0.1", "c" * 32,
    )
    assert invalid["edgeHeaderPresent"] is True
    assert invalid["edgeHeaderSingle"] is True
    assert invalid["edgeHeaderValid"] is False
    assert invalid["edgeFingerprint"] is None
