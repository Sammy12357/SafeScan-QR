"""CSP tightening is measured without changing enforcement or storing URLs."""

import importlib
import json
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(params=[False, True])
def csp_app(tmp_path, monkeypatch, request):
    enabled = request.param
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'csp.db'}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("CSP_REPORT_ONLY_ENABLED", "true" if enabled else "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    reports = importlib.import_module("hackabull.routes_csp_reports")
    reports._recent_reports.clear()
    yield enabled, app, reports, TestClient(app.qr_app, base_url="https://testserver")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def legacy_report(directive="style-src-attr"):
    return {"csp-report": {
        "effective-directive": directive,
        "document-uri": "https://testserver/private?token=SECRET-DO-NOT-STORE",
        "blocked-uri": "https://attacker.example/SECRET-DO-NOT-STORE",
        "script-sample": "SECRET-DO-NOT-STORE",
    }}


def test_report_only_header_is_opt_in_and_does_not_change_enforced_policy(csp_app):
    enabled, _, _, client = csp_app
    page = client.get("/")
    assert page.status_code == 200
    assert "style-src 'self' 'unsafe-inline'" in page.headers["content-security-policy"]
    if enabled:
        report_only = page.headers["content-security-policy-report-only"]
        assert "style-src 'self' https://fonts.googleapis.com" in report_only
        assert "'unsafe-inline'" not in report_only
        assert "report-uri /api/security/csp-report" in report_only
        assert "report-to safescan-csp" in report_only
        assert page.headers["reporting-endpoints"] == 'safescan-csp="/api/security/csp-report"'
    else:
        assert "content-security-policy-report-only" not in page.headers
        assert "reporting-endpoints" not in page.headers
    assert "content-security-policy-report-only" not in client.get("/health").headers
    assert "content-security-policy-report-only" not in client.get("/static/auth.js").headers


def test_disabled_receiver_does_not_process_reports(csp_app):
    enabled, _, reports, client = csp_app
    if enabled:
        pytest.skip("receiver is enabled in this fixture")
    response = client.post("/api/security/csp-report", json=legacy_report(),
                           headers={"Content-Type": "application/csp-report"})
    assert response.status_code == 404
    assert len(reports._recent_reports) == 0


def test_legacy_and_modern_reports_count_only_fixed_categories(csp_app, monkeypatch):
    enabled, app, reports, client = csp_app
    if not enabled:
        pytest.skip("receiver is disabled in this fixture")

    labels = []

    class Counter:
        def labels(self, **kwargs):
            labels.append(kwargs)
            return self

        def inc(self):
            pass

    monkeypatch.setattr(reports, "CSP_REPORTS", Counter())
    middleware = importlib.import_module("hackabull.app_module")
    monkeypatch.setattr(middleware, "get_session_user", lambda request: (_ for _ in ()).throw(AssertionError("account lookup")))
    monkeypatch.setattr(middleware, "validate_and_rotate_remember_me", lambda request: (_ for _ in ()).throw(AssertionError("remember-me lookup")))
    client.cookies.set(app.SESSION_COOKIE_NAME, "s" * 32)
    first = client.post("/api/security/csp-report", content=json.dumps(legacy_report()),
                        headers={"Content-Type": "application/csp-report"})
    modern = [{
        "type": "csp-violation", "url": "https://testserver/private?SECRET-DO-NOT-STORE",
        "body": {"effectiveDirective": directive, "sourceFile": "https://testserver/SECRET-DO-NOT-STORE"},
    } for directive in ("style-src-elem", "script-src", "style-src-attr;SECRET-DO-NOT-STORE")]
    second = client.post("/api/security/csp-report", content=json.dumps(modern),
                         headers={"Content-Type": "application/reports+json"})
    assert first.status_code == second.status_code == 204
    assert first.headers["cache-control"] == "no-store"
    assert "set-cookie" not in first.headers
    assert labels == [
        {"directive": "style-src-attr"}, {"directive": "style-src-elem"},
        {"directive": "other"}, {"directive": "other"},
    ]
    assert len(reports._recent_reports) == 4
    assert all(isinstance(value, float) for value in reports._recent_reports)
    assert not app.RATE_LIMITS, "CSP counts must bypass the IP-linked audit limiter"
    assert b"SECRET-DO-NOT-STORE" not in first.content + second.content


def test_receiver_rejects_oversize_invalid_and_unsupported_reports(csp_app):
    enabled, _, reports, client = csp_app
    if not enabled:
        pytest.skip("receiver is disabled in this fixture")
    path = "/api/security/csp-report"
    assert client.post(path, json=legacy_report()).status_code == 415
    assert client.post(path, content=b" " * (reports.MAX_BODY_BYTES + 1),
                       headers={"Content-Type": "application/csp-report"}).status_code == 413
    chunks = iter([b" " * 4000, b" " * 5000])
    assert client.post(path, content=chunks,
                       headers={"Content-Type": "application/csp-report"}).status_code == 413
    assert client.post(path, content="{", headers={"Content-Type": "application/csp-report"}).status_code == 400
    invalid = {"csp-report": {"effective-directive": ["style-src"]}}
    assert client.post(path, content=json.dumps(invalid),
                       headers={"Content-Type": "application/csp-report"}).status_code == 400
    assert len(reports._recent_reports) == 0


def test_report_budget_counts_batched_events_and_stays_bounded(csp_app, monkeypatch):
    enabled, _, reports, client = csp_app
    if not enabled:
        pytest.skip("receiver is disabled in this fixture")
    monkeypatch.setattr(reports, "REPORT_LIMIT_PER_MINUTE", 2)
    batch = [{"type": "csp-violation", "body": {"effectiveDirective": "style-src"}}] * 2
    path = "/api/security/csp-report"
    headers = {"Content-Type": "application/reports+json"}
    assert client.post(path, content=json.dumps(batch), headers=headers).status_code == 204
    blocked = client.post(path, content=json.dumps(batch[:1]), headers=headers)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "60"
    assert len(reports._recent_reports) == 2
