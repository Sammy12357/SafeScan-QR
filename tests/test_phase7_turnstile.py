"""Public bot checks must validate server-side before spending work or storing data."""

import importlib
import sqlite3
import sys

import pytest

from browser_client import BrowserTestClient
from test_auth_persistence import register


@pytest.fixture()
def turnstile_app(tmp_path, monkeypatch):
    db_path = tmp_path / "turnstile.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("TURNSTILE_ENABLED", "true")
    monkeypatch.setenv("TURNSTILE_SITE_KEY", "test-site-key")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("TURNSTILE_HOSTNAMES", "testserver")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    client = BrowserTestClient(app.qr_app, base_url="https://testserver")
    yield client, db_path, monkeypatch
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _count(db_path, table):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _data_form(token=None):
    data = {"email": "person@example.com", "region": "Canada", "request_type": "rectification", "details": "Please correct this."}
    if token is not None:
        data["cf-turnstile-response"] = token
    return data


def test_missing_token_blocks_report_and_data_request_before_side_effects(turnstile_app):
    client, db_path, monkeypatch = turnstile_app
    api = importlib.import_module("hackabull.routes_api")
    pages = importlib.import_module("hackabull.routes_pages")
    monkeypatch.setattr(api, "analyze_full_pipeline", lambda *_args: pytest.fail("No analysis before verification"))
    monkeypatch.setattr(pages, "send_email", lambda *_args: pytest.fail("No email before verification"))

    report = client.post("/api/report", json={"url": "https://example.com", "reason": "phishing"})
    request = client.post("/legal/data-request", data=_data_form())

    assert report.status_code == 400
    assert request.status_code == 400
    assert "security verification" in request.text.lower()
    assert _count(db_path, "url_reports") == 0
    assert _count(db_path, "data_requests") == 0


@pytest.mark.parametrize("result", [
    {"success": False, "hostname": "testserver", "action": "url_report"},
    {"success": True, "hostname": "attacker.example", "action": "url_report"},
    {"success": True, "hostname": "testserver", "action": "waitlist"},
    {"success": "true", "hostname": "testserver", "action": "url_report"},
])
def test_report_requires_exact_success_hostname_and_action(turnstile_app, result):
    client, db_path, monkeypatch = turnstile_app
    api = importlib.import_module("hackabull.routes_api")
    turnstile = importlib.import_module("hackabull.turnstile")
    monkeypatch.setattr(turnstile, "_siteverify", lambda _token: result)
    monkeypatch.setattr(api, "analyze_full_pipeline", lambda *_args: pytest.fail("No analysis before verification"))

    response = client.post("/api/report", json={
        "url": "https://example.com", "reason": "phishing", "turnstileToken": "opaque-token",
    })

    assert response.status_code == 400
    assert _count(db_path, "url_reports") == 0


def test_verified_guest_report_runs_analysis_once_and_is_saved(turnstile_app):
    client, db_path, monkeypatch = turnstile_app
    api = importlib.import_module("hackabull.routes_api")
    turnstile = importlib.import_module("hackabull.turnstile")
    events = []

    def siteverify(token):
        events.append(("verify", token))
        return {"success": True, "hostname": "testserver", "action": "url_report"}

    async def analyze(url):
        events.append(("analyze", url))
        return {"confidenceScore": 80}

    monkeypatch.setattr(turnstile, "_siteverify", siteverify)
    monkeypatch.setattr(api, "validate_public_url", lambda url: url)
    monkeypatch.setattr(api, "analyze_full_pipeline", analyze)
    response = client.post("/api/report", json={
        "url": "https://example.com", "reason": "phishing", "turnstileToken": "opaque-token",
    })

    assert response.status_code == 200
    assert response.json()["status"] == "pending"
    assert events == [("verify", "opaque-token"), ("analyze", "https://example.com")]
    assert _count(db_path, "url_reports") == 1


def test_valid_guest_data_request_is_saved_and_rate_limited(turnstile_app):
    client, db_path, monkeypatch = turnstile_app
    turnstile = importlib.import_module("hackabull.turnstile")
    seen = []

    def siteverify(token):
        seen.append(token)
        return {"success": True, "hostname": "testserver", "action": "data_request"}

    monkeypatch.setattr(turnstile, "_siteverify", siteverify)
    page = client.get("/legal/data-request")
    assert page.status_code == 200
    assert 'data-action="data_request"' in page.text
    assert "https://challenges.cloudflare.com" in page.headers["content-security-policy"]

    for index in range(3):
        response = client.post("/legal/data-request", data=_data_form(f"fresh-{index}"))
        assert response.status_code == 200
    limited = client.post("/legal/data-request", data=_data_form("fresh-3"))

    assert limited.status_code == 429
    assert limited.headers["retry-after"]
    assert seen == ["fresh-0", "fresh-1", "fresh-2"]
    assert _count(db_path, "data_requests") == 3


def test_authenticated_data_request_skips_guest_challenge_but_keeps_account_limit(turnstile_app):
    client, db_path, monkeypatch = turnstile_app
    scan_auth = importlib.import_module("hackabull.routes_scan_auth")
    turnstile = importlib.import_module("hackabull.turnstile")
    monkeypatch.setattr(scan_auth, "LOCAL_AUTH_ENABLED", True)
    monkeypatch.setattr(turnstile, "_siteverify", lambda _token: pytest.fail("Signed-in user needs no guest challenge"))
    assert register(client).status_code == 200

    for _ in range(5):
        response = client.post("/legal/data-request", data=_data_form())
        assert response.status_code == 200
    limited = client.post("/legal/data-request", data=_data_form())

    assert limited.status_code == 429
    assert _count(db_path, "data_requests") == 5


def test_provider_failure_and_missing_config_fail_closed(turnstile_app):
    client, db_path, monkeypatch = turnstile_app
    turnstile = importlib.import_module("hackabull.turnstile")
    monkeypatch.setattr(turnstile, "_siteverify", lambda _token: (_ for _ in ()).throw(ValueError("malformed response")))
    failed = client.post("/legal/data-request", data=_data_form("opaque-token"))
    assert failed.status_code == 503
    assert _count(db_path, "data_requests") == 0

    monkeypatch.setattr(turnstile, "TURNSTILE_SECRET_KEY", "")
    missing = client.post("/legal/data-request", data=_data_form("opaque-token"))
    assert missing.status_code == 503
    assert _count(db_path, "data_requests") == 0


def test_public_forms_and_frontend_have_widget_contract(turnstile_app):
    client, _, _ = turnstile_app
    opt_out = client.get("/legal/do-not-sell")
    assert 'data-action="data_request"' in opt_out.text
    assert '/static/turnstile-widgets.js' in opt_out.text
    assert "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" in opt_out.text


def test_siteverify_uses_bounded_request_without_forwarding_visitor_ip(turnstile_app):
    _, _, monkeypatch = turnstile_app
    turnstile = importlib.import_module("hackabull.turnstile")
    seen = {}

    class Response:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_content(self, *, chunk_size):
            assert chunk_size == 4096
            yield b'{"success":true,"hostname":"testserver","action":"url_report"}'

    def post(url, **kwargs):
        seen.update({"url": url, **kwargs})
        return Response()

    monkeypatch.setattr(turnstile.requests, "post", post)
    assert turnstile._siteverify("opaque-token")["success"] is True
    assert seen["url"] == turnstile.SITEVERIFY_URL
    assert seen["data"] == {"secret": "test-secret-key", "response": "opaque-token"}
    assert seen["timeout"] == (2, 3)
    assert seen["allow_redirects"] is False
    assert seen["stream"] is True


def test_oversize_siteverify_response_fails_closed(turnstile_app):
    _, _, monkeypatch = turnstile_app
    turnstile = importlib.import_module("hackabull.turnstile")

    class Response:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_content(self, *, chunk_size):
            yield b"x" * 4096
            yield b"x" * 4096
            yield b"x"

    monkeypatch.setattr(turnstile.requests, "post", lambda *_args, **_kwargs: Response())
    with pytest.raises(ValueError, match="too large"):
        turnstile._siteverify("opaque-token")


def test_siteverify_has_absolute_deadline_for_trickling_response(turnstile_app):
    _, _, monkeypatch = turnstile_app
    turnstile = importlib.import_module("hackabull.turnstile")

    class Response:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_content(self, *, chunk_size):
            yield b"{"
            yield b'"success":true}'

    times = iter([0, 1, 9])
    monkeypatch.setattr(turnstile.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(turnstile.requests, "post", lambda *_args, **_kwargs: Response())
    with pytest.raises(ValueError, match="timed out"):
        turnstile._siteverify("opaque-token")
