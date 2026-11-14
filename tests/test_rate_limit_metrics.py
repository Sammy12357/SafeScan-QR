"""Bounded request budgets and low-cardinality observability labels."""

import asyncio
import importlib
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response


@pytest.fixture()
def app_modules(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'limits.db'}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    security = importlib.import_module("hackabull.security")
    app_module = importlib.import_module("hackabull.app_module")
    app.RATE_LIMITS.clear()
    yield app, security, app_module
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _request(ip):
    return Request({
        "type": "http", "method": "GET", "path": "/api/scan",
        "headers": [], "client": (ip, 50000), "server": ("testserver", 443),
        "scheme": "https", "query_string": b"",
    })


def test_rate_limit_buckets_have_a_fixed_memory_ceiling(app_modules):
    app, security, _ = app_modules
    for index in range(5000):
        assert security.enforce_rate_limit(_request(f"198.51.{index // 256}.{index % 256}"), "flood", 2, 60) is None
    assert len(app.RATE_LIMITS) <= 4096


def test_account_and_ip_budgets_are_both_enforced(app_modules):
    _, security, _ = app_modules
    first = _request("198.51.100.1")
    second = _request("198.51.100.2")
    assert security.enforce_rate_limit(first, "scan", 2, 60, user_key="alice", ip_limit=3) is None
    assert security.enforce_rate_limit(second, "scan", 2, 60, user_key="alice", ip_limit=3) is None
    assert security.enforce_rate_limit(first, "scan", 2, 60, user_key="alice", ip_limit=3).status_code == 429
    assert security.enforce_rate_limit(first, "scan", 2, 60, user_key="bob", ip_limit=3) is None
    assert security.enforce_rate_limit(first, "scan", 2, 60, user_key="carol", ip_limit=3) is None
    assert security.enforce_rate_limit(first, "scan", 2, 60, user_key="dave", ip_limit=3).status_code == 429


def test_rate_limit_window_expires_and_retry_after_is_reported(app_modules, monkeypatch):
    _, security, _ = app_modules
    current = [1000.0]
    monkeypatch.setattr(security.time, "time", lambda: current[0])
    request = _request("198.51.100.11")
    assert security.enforce_rate_limit(request, "window", 2, 60) is None
    current[0] = 1010.0
    assert security.enforce_rate_limit(request, "window", 2, 60) is None
    current[0] = 1011.0
    blocked = security.enforce_rate_limit(request, "window", 2, 60)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "49"
    current[0] = 1060.0
    assert security.enforce_rate_limit(request, "window", 2, 60) is None


def test_metrics_use_route_template_and_single_unmatched_label(app_modules, monkeypatch):
    app, _, app_module = app_modules
    paths = []

    class Metric:
        def labels(self, **kwargs):
            paths.append(kwargs["path"])
            return self

        def inc(self):
            pass

        def observe(self, duration):
            pass

    monkeypatch.setattr(app_module, "REQUEST_COUNT", Metric())
    monkeypatch.setattr(app_module, "REQUEST_LATENCY", Metric())
    client = TestClient(app.qr_app, base_url="https://testserver")
    client.get("/admin/users/alice@example.com/drawer")
    for index in range(20):
        client.get(f"/random-not-found-{index}")

    async def probe_unmatched_cardinality():
        async def not_found(request):
            return Response(status_code=404)

        for index in range(10_000):
            request = _request("198.51.100.42")
            request.scope["path"] = f"/random-not-found-{index + 20}"
            await app_module.metrics_middleware(request, not_found)

    asyncio.run(probe_unmatched_cardinality())

    assert set(paths) == {"/admin/users/{email}/drawer", "unmatched"}
