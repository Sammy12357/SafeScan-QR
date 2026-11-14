"""Client IP identity must not come from headers a visitor can supply."""

import importlib
import sys

import pytest
from starlette.requests import Request


@pytest.fixture()
def ip_modules(tmp_path, monkeypatch):
    # CI's default SQLite URL is relative. Import the application only after
    # directing its import-time schema setup to this test's absolute temp path.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'client-ip.db'}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    module = importlib.import_module("hackabull")
    module.RATE_LIMITS.clear()
    yield module
    module.RATE_LIMITS.clear()
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def make_request(headers=(), peer="198.51.100.9"):
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(name.lower().encode(), value.encode()) for name, value in headers],
        "client": (peer, 50000) if peer else None,
        "server": ("testserver", 443),
    })


def test_direct_request_ignores_every_forwarded_ip_header(monkeypatch, ip_modules):
    monkeypatch.delenv("RENDER", raising=False)
    request = make_request([
        ("X-Forwarded-For", "127.0.0.1, 198.51.100.9"),
        ("CF-Connecting-IP", "192.0.2.42"),
        ("True-Client-IP", "203.0.113.42"),
    ])
    assert ip_modules.request_ip(request) == "198.51.100.9"


def test_render_uses_only_edge_authored_single_ip(monkeypatch, ip_modules):
    monkeypatch.setenv("RENDER", "true")
    request = make_request([
        ("X-Forwarded-For", "127.0.0.1, 198.51.100.9"),
        ("True-Client-IP", "203.0.113.42"),
        ("CF-Connecting-IP", "2001:db8::1"),
    ])
    assert ip_modules.request_ip(request) == "2001:db8::1"
    assert ip_modules.qr_request_client_identity(request) == "2001:db8::1"


def test_render_rejects_missing_malformed_and_duplicate_edge_headers(monkeypatch, ip_modules):
    monkeypatch.setenv("RENDER", "true")
    for headers in (
        [("X-Forwarded-For", "127.0.0.1")],
        [("True-Client-IP", "127.0.0.1")],
        [("CF-Connecting-IP", "127.0.0.1, 203.0.113.9")],
        [("CF-Connecting-IP", "203.0.113.9"), ("CF-Connecting-IP", "192.0.2.9")],
        [("CF-Connecting-IP", "invalid")],
        [("CF-Connecting-IP", " 203.0.113.9")],
        [("CF-Connecting-IP", "203.0.113.9:443")],
    ):
        request = make_request(headers)
        assert ip_modules.request_ip(request) is None
        assert ip_modules.qr_request_client_identity(request).startswith("unverified-ingress:")


def test_render_normalizes_ipv4_mapped_ipv6(monkeypatch, ip_modules):
    monkeypatch.setenv("RENDER", "true")
    request = make_request([("CF-Connecting-IP", "::ffff:203.0.113.9")])
    assert ip_modules.request_ip(request) == "203.0.113.9"


def test_xff_rotation_cannot_bypass_direct_rate_limit(monkeypatch, ip_modules):
    monkeypatch.delenv("RENDER", raising=False)
    ip_modules.RATE_LIMITS.clear()
    try:
        first = make_request([("X-Forwarded-For", "192.0.2.1")])
        second = make_request([("X-Forwarded-For", "192.0.2.2")])
        assert ip_modules.enforce_rate_limit(first, "ip_spoof_regression", 1, 60) is None
        assert ip_modules.enforce_rate_limit(second, "ip_spoof_regression", 1, 60).status_code == 429
    finally:
        ip_modules.RATE_LIMITS.clear()


def test_render_missing_edge_header_still_has_a_rate_limit(monkeypatch, ip_modules):
    monkeypatch.setenv("RENDER", "true")
    ip_modules.RATE_LIMITS.clear()
    try:
        first = make_request([("X-Forwarded-For", "192.0.2.1")])
        second = make_request([("X-Forwarded-For", "192.0.2.2")])
        assert ip_modules.enforce_rate_limit(first, "unverified_ingress_regression", 1, 60) is None
        assert ip_modules.enforce_rate_limit(second, "unverified_ingress_regression", 1, 60).status_code == 429
    finally:
        ip_modules.RATE_LIMITS.clear()


def test_render_limit_is_per_edge_client_on_both_public_domains(monkeypatch, ip_modules):
    monkeypatch.setenv("RENDER", "true")
    ip_modules.RATE_LIMITS.clear()
    try:
        first = make_request([
            ("Host", "sqafe.com"),
            ("CF-Connecting-IP", "203.0.113.10"),
            ("X-Forwarded-For", "192.0.2.1"),
        ])
        same_client_other_domain = make_request([
            ("Host", "safescan-qr.onrender.com"),
            ("CF-Connecting-IP", "203.0.113.10"),
            ("X-Forwarded-For", "192.0.2.2"),
        ])
        other_client = make_request([
            ("Host", "sqafe.com"),
            ("CF-Connecting-IP", "203.0.113.11"),
            ("X-Forwarded-For", "192.0.2.1"),
        ])
        assert ip_modules.enforce_rate_limit(first, "render_client_regression", 1, 60) is None
        assert ip_modules.enforce_rate_limit(same_client_other_domain, "render_client_regression", 1, 60).status_code == 429
        assert ip_modules.enforce_rate_limit(other_client, "render_client_regression", 1, 60) is None
    finally:
        ip_modules.RATE_LIMITS.clear()
