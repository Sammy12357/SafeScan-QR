"""Security alerts are bounded, redacted, and inert until explicitly enabled."""

import importlib
import sqlite3
import sys

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


@pytest.fixture()
def alert_app(tmp_path, monkeypatch):
    database = tmp_path / "alerts.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("SECURITY_ALERTS_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    alerts = importlib.import_module("hackabull.security_alerts")
    yield app, alerts, database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def test_alerts_are_off_by_default_and_ignore_unknown_names(alert_app):
    _, alerts, _ = alert_app
    assert alerts.ENABLED is False
    assert alerts.record_security_event("auth.failed") is None
    assert alerts.MONITOR.retained_count() == 0
    monitor = alerts.SecurityAlertMonitor(enabled=True, dispatch=lambda _alert: pytest.fail("unknown event"))
    assert monitor.record("user-supplied-event") is None
    assert monitor.retained_count() == 0


def test_threshold_cooldown_and_memory_bound(alert_app):
    _, alerts, _ = alert_app
    clock = [1000.0]
    dispatched = []
    monitor = alerts.SecurityAlertMonitor(
        enabled=True,
        rules={"auth.failed": (3, 60)},
        cooldown=120,
        clock=lambda: clock[0],
        dispatch=dispatched.append,
    )
    assert monitor.record("auth.failed") is None
    assert monitor.record("auth.failed") is None
    assert monitor.record("auth.failed") == alerts.Alert("auth.failed", 3, 60)
    for _ in range(10000):
        monitor.record("auth.failed")
    assert len(dispatched) == 1
    assert monitor.retained_count() == 3
    clock[0] += 61
    assert monitor.record("auth.failed") is None
    assert monitor.retained_count() == 1
    clock[0] += 120
    monitor.record("auth.failed")
    monitor.record("auth.failed")
    monitor.record("auth.failed")
    assert len(dispatched) == 2


def test_enqueue_failure_never_breaks_request_and_retries_after_backoff(alert_app):
    _, alerts, _ = alert_app
    clock = [1000.0]
    attempts = []

    def unavailable(_alert):
        attempts.append(clock[0])
        raise RuntimeError("queue full")

    monitor = alerts.SecurityAlertMonitor(
        enabled=True, rules={"api_key.created": (1, 600)},
        cooldown=600, clock=lambda: clock[0], dispatch=unavailable,
    )
    assert monitor.record("api_key.created") is None
    assert monitor.record("api_key.created") is None
    clock[0] += 30
    assert monitor.record("api_key.created") is None
    assert attempts == [1000.0, 1030.0]


def _request(path):
    return Request({
        "type": "http", "method": "GET", "scheme": "https", "path": path,
        "root_path": "", "server": ("testserver", 443),
        "client": ("198.51.100.44", 1234), "headers": [(b"user-agent", b"private-agent")],
    })


def test_audit_hook_sends_fixed_event_names_without_private_metadata(alert_app, monkeypatch):
    _, alerts, database = alert_app
    audit = importlib.import_module("hackabull.audit")
    emitted = []
    monitor = alerts.SecurityAlertMonitor(
        enabled=True,
        rules={code: (1, 600) for code in alerts.DEFAULT_RULES},
        cooldown=0,
        dispatch=emitted.append,
    )
    monkeypatch.setattr(alerts, "MONITOR", monitor)
    audit.audit_log("auth.permission_denied", request=_request("/profile"), metadata={"secret": "never-send"})
    assert emitted == []
    audit.audit_log("auth.permission_denied", request=_request("/admin/users"), metadata={"secret": "never-send"})
    for action in ("auth.failed", "admin.role_changed", "api_key.created", "airdrop.sweep_executed", "airdrop.sweep_failed"):
        audit.audit_log(action, request=_request("/admin"), actor_user_id="private-user", metadata={"url": "https://private.example"})
    assert [alert.code for alert in emitted] == [
        "auth.permission_denied.admin", "auth.failed", "admin.role_changed",
        "api_key.created", "airdrop.sweep_executed", "airdrop.sweep_failed",
    ]
    assert all(alert.count == 1 and alert.window_seconds == 600 for alert in emitted)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 7


def test_stripe_bad_signature_records_redacted_event(alert_app, monkeypatch):
    app, alerts, database = alert_app
    payments = importlib.import_module("hackabull.payments_stripe")
    monkeypatch.setattr(payments, "STRIPE_WEBHOOK_SECRET", "test-secret")
    emitted = []
    monkeypatch.setattr(alerts, "MONITOR", alerts.SecurityAlertMonitor(
        enabled=True, rules={"stripe.signature_failed": (1, 600)}, dispatch=emitted.append,
    ))
    client = TestClient(app.qr_app, base_url="https://testserver")
    response = client.post("/webhooks/stripe", content=b"private-payment-body", headers={"stripe-signature": "bad"})
    assert response.status_code == 400
    assert [alert.code for alert in emitted] == ["stripe.signature_failed"]
    with sqlite3.connect(database) as conn:
        row = conn.execute("SELECT metadata, ip_address, user_agent FROM audit_logs WHERE action = 'stripe.signature_failed'").fetchone()
    assert row == ("{}", None, None)


def test_5xx_response_records_count_without_path(alert_app, monkeypatch):
    app, alerts, _ = alert_app
    emitted = []
    monkeypatch.setattr(alerts, "MONITOR", alerts.SecurityAlertMonitor(
        enabled=True, rules={"http.5xx": (1, 300)}, dispatch=emitted.append,
    ))

    @app.qr_app.get("/__monitor_test_failure")
    async def failed_route():
        return JSONResponse({"error": "private content"}, status_code=503)

    response = TestClient(app.qr_app, base_url="https://testserver").get("/__monitor_test_failure")
    assert response.status_code == 503
    assert emitted == [alerts.Alert("http.5xx", 1, 300)]


def test_delivery_is_fixed_redacted_and_only_to_valid_discord_host(alert_app, monkeypatch):
    _, alerts, _ = alert_app
    assert alerts._valid_discord_webhook("https://discord.com/api/webhooks/123/opaque_token")
    assert not alerts._valid_discord_webhook("https://discord.com.evil.example/api/webhooks/123/token")
    assert not alerts._valid_discord_webhook("http://discord.com/api/webhooks/123/token")
    assert not alerts._valid_discord_webhook("https://discord.com:invalid/api/webhooks/123/token")
    monkeypatch.setattr(alerts, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/123/opaque_token")
    monkeypatch.setattr(alerts, "EMAIL_TO", "")
    sent = []

    class Result:
        status_code = 204

    def fake_post(url, **kwargs):
        sent.append((url, kwargs))
        return Result()

    monkeypatch.setattr(alerts.requests, "post", fake_post)
    alerts._deliver(alerts.Alert("auth.failed", 20, 600))
    assert len(sent) == 1
    assert sent[0][1]["timeout"] == (2, 5)
    assert sent[0][1]["allow_redirects"] is False
    body = sent[0][1]["json"]["content"]
    assert "auth.failed" in body
    assert "private-user" not in body and "198.51.100.44" not in body
    with pytest.raises(ValueError):
        alerts._deliver(alerts.Alert("email=private@example.org", 1, 600))


def test_enabled_alerts_require_valid_destination(alert_app, monkeypatch):
    _, alerts, _ = alert_app
    monkeypatch.setattr(alerts, "ENABLED", True)
    monkeypatch.setattr(alerts, "DISCORD_WEBHOOK_URL", "")
    monkeypatch.setattr(alerts, "EMAIL_TO", "")
    with pytest.raises(RuntimeError, match="without a delivery destination"):
        alerts.validate_alert_configuration()
    monkeypatch.setattr(alerts, "DISCORD_WEBHOOK_URL", "https://evil.example/api/webhooks/1/token")
    with pytest.raises(RuntimeError, match="Invalid security alert Discord"):
        alerts.validate_alert_configuration()
    monkeypatch.setattr(alerts, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1/token")
    alerts.validate_alert_configuration()
