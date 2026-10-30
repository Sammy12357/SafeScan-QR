import importlib
import json
import os
import sqlite3
import sys
import time

from fastapi.testclient import TestClient


def load_app(tmp_path, monkeypatch):
    db_path = tmp_path / "app.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("METRICS_ALLOWED_IPS", "testclient,127.0.0.1,::1")
    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    module = importlib.import_module("hackabull")
    module.RATE_LIMITS.clear()
    return module, TestClient(module.qr_app, base_url="https://testserver"), db_path


def test_local_storage_persists_upload_artifact(tmp_path, monkeypatch):
    module, _, db_path = load_app(tmp_path, monkeypatch)
    artifact = module.persist_qr_upload(
        b"qr-bytes",
        "scan.png",
        "image/png",
        {"google_id": "user_1", "email": "user@example.com"},
    )

    assert artifact["backend"] == "local"
    assert (tmp_path / "uploads" / artifact["key"]).exists()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT object_key, backend, byte_size FROM upload_artifacts").fetchone()
    assert row == (artifact["key"], "local", 8)


def test_readiness_and_metrics_endpoints(tmp_path, monkeypatch):
    _, client, _ = load_app(tmp_path, monkeypatch)

    ready = client.get("/health/ready")
    metrics = client.get("/metrics")

    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert metrics.status_code == 200
    assert b"safescan_requests_total" in metrics.content or b"prometheus-client is not installed" in metrics.content


def test_provider_health_reports_configuration_without_secrets(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "legacy-secret-value")
    monkeypatch.delenv("SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret-value")
    monkeypatch.delenv("SAFESCAN_VIRUSTOTAL_LICENSED", raising=False)
    _, client, _ = load_app(tmp_path, monkeypatch)

    degraded = client.get("/health/providers")
    ready = client.get("/health/ready")

    assert degraded.status_code == 200
    assert degraded.json() == {
        "status": "incomplete",
        "scope": "configuration_and_local_feed_only",
        "providers": {
            "google": "legacy_key_disabled",
            "phishtank": "terms_not_confirmed",
            "phishtankFeedAgeSeconds": None,
            "virustotal": "license_confirmation_required",
            "completeChecksConfigured": False,
        },
    }
    assert ready.status_code == 200
    assert "legacy-secret-value" not in degraded.text
    assert "vt-secret-value" not in degraded.text

    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "web-risk-secret-value")
    monkeypatch.setenv("PHISHTANK_APP_KEY", "phish-test-key")
    monkeypatch.setenv("SAFESCAN_PHISHTANK_TERMS_CONFIRMED", "true")
    feed = importlib.import_module("hackabull.phish_feed")
    feed._write_snapshot(
        b"url,verified,online\nhttps://known-phish.example/,yes,yes\n",
        feed._feed_path(),
        time.time(),
    )
    configured = client.get("/health/providers")
    assert configured.json()["status"] == "configured"
    assert configured.json()["providers"]["google"] == "web_risk_configured"
    assert configured.json()["providers"]["phishtank"] == "fresh"
    assert configured.json()["providers"]["virustotal"] == "license_confirmation_required"
    assert configured.json()["providers"]["completeChecksConfigured"] is True
    assert "web-risk-secret-value" not in configured.text
    assert "phish-test-key" not in configured.text


def test_scan_history_persists_classification(tmp_path, monkeypatch):
    module, _, db_path = load_app(tmp_path, monkeypatch)

    module.save_scan_history(
        "user@example.com",
        "https://example.test",
        {
            "status": "MALICIOUS",
            "score": 92,
            "reasons": [{
                "label": "Very long malicious reputation finding",
                "severity": "high",
                "detail": "x" * 500,
                "metadata": {"large": "y" * 1000},
            }],
        },
    )

    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT verdict, risk_score, classification, signals FROM scan_history").fetchone()

    signals = json.loads(row[3])
    assert row[:3] == ("MALICIOUS", 92, "MALICIOUS")
    assert len(row[3]) < 260
    assert signals == [{
        "label": "Very long malicious reputation finding",
        "severity": "high",
        "detail": ("x" * 119) + "...",
    }]
