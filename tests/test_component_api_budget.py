"""Public component checks share a bounded quota before doing costly work."""

import importlib
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request


@pytest.fixture()
def component_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'component.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_api")
    budget = importlib.import_module("hackabull.component_budget")
    app.RATE_LIMITS.clear()
    monkeypatch.setattr(routes, "validate_public_url", lambda url: url)
    calls = []
    monkeypatch.setattr(routes, "check_domain_intelligence", lambda url: calls.append("domain") or [])
    monkeypatch.setattr(routes, "check_crypto_pattern_signals", lambda url: calls.append("crypto") or [])
    monkeypatch.setattr(routes, "google_reputation_signal", lambda url: calls.append("google") or {"check": "Google Web Risk", "verified": True})
    monkeypatch.setattr(routes, "phishtank_signal", lambda url: {"check": "PhishTank", "verified": True})
    monkeypatch.setattr(routes, "trace_redirect_chain", lambda url: calls.append("redirect") or {"redirectChain": []})
    yield TestClient(app.qr_app, base_url="https://testserver"), budget, calls
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def test_component_routes_share_ten_per_hour_client_quota(component_app):
    client, _, calls = component_app
    for _ in range(5):
        assert client.post("/api/check-domain", json={"url": "https://example.org"}).status_code == 200
        assert client.post("/api/check-crypto-patterns", json={"url": "https://example.org"}).status_code == 200

    blocked = client.post("/api/check-reputation", json={"url": "https://example.org"})
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert calls.count("domain") == calls.count("crypto") == 5
    assert "google" not in calls


def test_outbound_component_routes_share_five_per_hour_client_quota(component_app):
    client, _, calls = component_app
    for _ in range(5):
        assert client.post("/api/trace-redirects", json={"url": "https://example.org"}).status_code == 200

    blocked = client.post("/api/check-reputation", json={"url": "https://example.org"})
    assert blocked.status_code == 429
    assert calls == ["redirect"] * 5
    # A cheap component check can still use the rest of the overall quota.
    assert client.post("/api/check-domain", json={"url": "https://example.org"}).status_code == 200


def test_global_outbound_cap_remains_when_forwarded_identity_changes(component_app):
    client, _, calls = component_app
    for index in range(60):
        response = client.post(
            "/api/check-reputation",
            json={"url": "https://example.org"},
            headers={"X-Forwarded-For": f"198.51.100.{index + 1}"},
        )
        assert response.status_code == 200

    blocked = client.post(
        "/api/check-reputation", json={"url": "https://example.org"},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert blocked.status_code == 429
    assert calls.count("google") == 60


def test_component_budget_has_fixed_memory_ceiling_and_no_raw_ips(component_app, monkeypatch):
    _, budget_module, _ = component_app
    budget = budget_module.ComponentBudget()
    monkeypatch.setattr(budget, "MAX_CLIENTS", 16)
    monkeypatch.setattr(budget, "GLOBAL_LIMIT", 1000)
    for index in range(100):
        request = Request({
            "type": "http", "method": "POST", "path": "/api/check-domain",
            "headers": [], "client": (f"198.51.{index // 256}.{index % 256}", 12345),
            "server": ("testserver", 443), "scheme": "https", "query_string": b"",
        })
        assert budget.check(request) is None
    assert len(budget._clients) == 16
    assert all("198.51" not in key for key in budget._clients)


def test_component_budget_expires_old_calls(component_app, monkeypatch):
    _, budget_module, _ = component_app
    budget = budget_module.ComponentBudget()
    monkeypatch.setattr(budget, "CLIENT_LIMIT", 1)
    clock = [1000.0]
    monkeypatch.setattr(budget_module.time, "monotonic", lambda: clock[0])
    request = Request({
        "type": "http", "method": "POST", "path": "/api/check-domain",
        "headers": [], "client": ("198.51.100.10", 12345),
        "server": ("testserver", 443), "scheme": "https", "query_string": b"",
    })
    assert budget.check(request) is None
    clock[0] = 1001.0
    blocked = budget.check(request)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "3600"
    clock[0] = 4600.0
    assert budget.check(request) is None
