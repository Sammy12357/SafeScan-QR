"""The redirect tracer must connect only to DNS addresses it validated."""

import importlib
import socket
import sys

import pytest
import requests


@pytest.fixture()
def security(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'ssrf.db').as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    module = importlib.import_module("hackabull.security")
    yield module
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def dns_answer(ip, port=443):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class RawResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.closed = False
        self.released = False

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


def test_dns_rebinding_to_private_address_is_blocked_before_connect(security, monkeypatch):
    lookups = iter([dns_answer("93.184.215.14"), dns_answer("127.0.0.1")])
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *args, **kwargs: next(lookups))
    monkeypatch.setattr(security.urllib3, "HTTPSConnectionPool", lambda *args, **kwargs: pytest.fail("Network connection attempted"))

    with pytest.raises(security.SafeScanError, match="Private"):
        security.follow_safe_redirects("https://example.org/path")


def test_mixed_public_private_dns_answers_are_rejected(security, monkeypatch):
    answers = dns_answer("93.184.215.14") + dns_answer("169.254.169.254")
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *args, **kwargs: answers)
    monkeypatch.setattr(security.urllib3, "HTTPSConnectionPool", lambda *args, **kwargs: pytest.fail("Network connection attempted"))

    with pytest.raises(security.SafeScanError, match="Private"):
        security.follow_safe_redirects("https://example.org/path")


def test_public_ip_is_pinned_with_original_host_and_verified_tls(security, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *args, **kwargs: dns_answer("93.184.215.14"))
    monkeypatch.setattr(security.requests, "Session", lambda: pytest.fail("Proxy-aware requests session used"))
    calls = []
    raw = RawResponse(200, {"Content-Type": "text/html"})

    class FakePool:
        def __init__(self, address, **kwargs):
            calls.append(("pool", address, kwargs))

        def urlopen(self, method, target, **kwargs):
            calls.append(("request", method, target, kwargs))
            return raw

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(security.urllib3, "HTTPSConnectionPool", FakePool)

    responses = security.follow_safe_redirects("https://example.org/some/path?a=1#fragment")

    assert len(responses) == 1
    assert responses[0].url == "https://example.org/some/path?a=1#fragment"
    assert responses[0].status_code == 200
    assert calls[0][1] == "93.184.215.14"
    assert calls[0][2]["server_hostname"] == "example.org"
    assert calls[0][2]["assert_hostname"] == "example.org"
    assert calls[0][2]["cert_reqs"] == "CERT_REQUIRED"
    assert calls[1][2] == "/some/path?a=1"
    assert calls[1][3]["headers"]["Host"] == "example.org"
    assert calls[1][3]["redirect"] is False
    assert calls[1][3]["preload_content"] is False
    assert raw.closed and raw.released


def test_internal_redirect_is_rejected_before_second_fetch(security, monkeypatch):
    monkeypatch.setattr(security.socket, "getaddrinfo", lambda *args, **kwargs: dns_answer("93.184.215.14"))
    calls = []

    class FakePool:
        def __init__(self, address, **kwargs):
            calls.append(address)

        def urlopen(self, *args, **kwargs):
            return RawResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"})

        def close(self):
            return None

    monkeypatch.setattr(security.urllib3, "HTTPSConnectionPool", FakePool)

    with pytest.raises(security.SafeScanError, match="Private"):
        security.follow_safe_redirects("https://example.org/redirect")

    assert calls == ["93.184.215.14"]


def test_unsupported_redirect_scheme_is_rejected(security):
    with pytest.raises(security.SafeScanError, match="http and https"):
        security.validate_public_url("ftp://example.org/file")


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@example.org/",
        "https://[invalid/",
        "https://\ud800.example.org/",
    ],
)
def test_hostile_url_syntax_is_rejected_without_server_error(security, url):
    with pytest.raises(security.SafeScanError):
        security.validate_public_url(url)


def test_redirect_hop_count_is_bounded(security, monkeypatch):
    calls = []

    def self_redirect(url, timeout):
        calls.append(url)
        result = requests.Response()
        result.status_code = 302
        result.url = url
        result.headers = requests.structures.CaseInsensitiveDict({"Location": url})
        return result

    monkeypatch.setattr(security, "is_private_hostname", lambda _: False)
    monkeypatch.setattr(security, "_fetch_pinned_url", self_redirect)

    with pytest.raises(requests.TooManyRedirects):
        security.follow_safe_redirects("https://example.org/loop", max_redirects=999)

    assert len(calls) == 11
