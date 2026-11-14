"""Client IP identity must not come from headers a visitor can supply."""

from starlette.requests import Request

from hackabull.config import RATE_LIMITS
from hackabull.request_helpers import request_ip
from hackabull.security import enforce_rate_limit
from hackabull.app_module import qr_request_client_identity


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


def test_direct_request_ignores_every_forwarded_ip_header(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    request = make_request([
        ("X-Forwarded-For", "127.0.0.1, 198.51.100.9"),
        ("CF-Connecting-IP", "192.0.2.42"),
        ("True-Client-IP", "203.0.113.42"),
    ])
    assert request_ip(request) == "198.51.100.9"


def test_render_uses_only_edge_authored_single_ip(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    request = make_request([
        ("X-Forwarded-For", "127.0.0.1, 198.51.100.9"),
        ("True-Client-IP", "203.0.113.42"),
        ("CF-Connecting-IP", "2001:db8::1"),
    ])
    assert request_ip(request) == "2001:db8::1"
    assert qr_request_client_identity(request) == "2001:db8::1"


def test_render_rejects_missing_malformed_and_duplicate_edge_headers(monkeypatch):
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
        assert request_ip(request) is None
        assert qr_request_client_identity(request).startswith("unverified-ingress:")


def test_render_normalizes_ipv4_mapped_ipv6(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    request = make_request([("CF-Connecting-IP", "::ffff:203.0.113.9")])
    assert request_ip(request) == "203.0.113.9"


def test_xff_rotation_cannot_bypass_direct_rate_limit(monkeypatch, tmp_path):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'audit.db'}")
    RATE_LIMITS.clear()
    try:
        first = make_request([("X-Forwarded-For", "192.0.2.1")])
        second = make_request([("X-Forwarded-For", "192.0.2.2")])
        assert enforce_rate_limit(first, "ip_spoof_regression", 1, 60) is None
        assert enforce_rate_limit(second, "ip_spoof_regression", 1, 60).status_code == 429
    finally:
        RATE_LIMITS.clear()


def test_render_missing_edge_header_still_has_a_rate_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'audit.db'}")
    RATE_LIMITS.clear()
    try:
        first = make_request([("X-Forwarded-For", "192.0.2.1")])
        second = make_request([("X-Forwarded-For", "192.0.2.2")])
        assert enforce_rate_limit(first, "unverified_ingress_regression", 1, 60) is None
        assert enforce_rate_limit(second, "unverified_ingress_regression", 1, 60).status_code == 429
    finally:
        RATE_LIMITS.clear()


def test_render_limit_is_per_edge_client_on_both_public_domains(monkeypatch, tmp_path):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'audit.db'}")
    RATE_LIMITS.clear()
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
        assert enforce_rate_limit(first, "render_client_regression", 1, 60) is None
        assert enforce_rate_limit(same_client_other_domain, "render_client_regression", 1, 60).status_code == 429
        assert enforce_rate_limit(other_client, "render_client_regression", 1, 60) is None
    finally:
        RATE_LIMITS.clear()
