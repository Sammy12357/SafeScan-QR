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
    monkeypatch.setenv("METRICS_TOKEN", "test-metrics-bearer-secret-32-characters")
    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    module = importlib.import_module("hackabull")
    module.RATE_LIMITS.clear()
    return module, TestClient(module.qr_app, base_url="https://testserver"), db_path


def test_upload_artifact_requires_explicit_retention(tmp_path, monkeypatch):
    module, _, db_path = load_app(tmp_path, monkeypatch)
    assert module.persist_qr_upload(b"qr-bytes", "scan.png", "image/png", None) is None
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM upload_artifacts").fetchone()[0] == 0
    assert not (tmp_path / "uploads").exists()

    artifact = module.persist_qr_upload(
        b"qr-bytes",
        "scan.png",
        "image/png",
        {"google_id": "user_1", "email": "user@example.com"},
        retain=True,
    )

    assert artifact["backend"] == "local"
    assert (tmp_path / "uploads" / artifact["key"]).exists()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT object_key, backend, byte_size FROM upload_artifacts").fetchone()
    assert row == (artifact["key"], "local", 8)


def test_readiness_and_metrics_endpoints(tmp_path, monkeypatch):
    _, client, _ = load_app(tmp_path, monkeypatch)

    ready = client.get("/health/ready")
    unauthenticated = client.get("/metrics")
    spoofed = client.get("/metrics", headers={"X-Forwarded-For": "127.0.0.1"})
    metrics = client.get("/metrics", headers={"Authorization": "Bearer test-metrics-bearer-secret-32-characters"})

    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert unauthenticated.status_code == 403
    assert spoofed.status_code == 403
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong-token"}).status_code == 403
    assert client.get("/metrics", headers={"Authorization": "Basic test-metrics-bearer-secret-32-characters"}).status_code == 403
    assert metrics.status_code == 200
    assert metrics.headers["cache-control"] == "no-store"
    assert b"safescan_requests_total" in metrics.content or b"prometheus-client is not installed" in metrics.content


def test_metrics_fail_closed_without_token(tmp_path, monkeypatch):
    _, client, _ = load_app(tmp_path, monkeypatch)
    monkeypatch.delenv("METRICS_TOKEN", raising=False)
    assert client.get("/metrics", headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403
    assert client.get("/metrics", headers={"Authorization": "Bearer test-metrics-bearer-secret-32-characters"}).status_code == 403
    monkeypatch.setenv("METRICS_TOKEN", "short")
    assert client.get("/metrics", headers={"Authorization": "Bearer short"}).status_code == 403


def test_metrics_use_bounded_route_labels_without_private_paths(tmp_path, monkeypatch):
    _, client, _ = load_app(tmp_path, monkeypatch)
    app_module = importlib.import_module("hackabull.app_module")

    class MetricRecorder:
        def __init__(self):
            self.label_sets = []

        def labels(self, **labels):
            self.label_sets.append(labels)
            return self

        def inc(self):
            return None

        def observe(self, _duration):
            return None

    requests = MetricRecorder()
    latencies = MetricRecorder()
    monkeypatch.setattr(app_module, "REQUEST_COUNT", requests)
    monkeypatch.setattr(app_module, "REQUEST_LATENCY", latencies)

    private_email = "private-metrics-test@example.invalid"
    client.get(f"/admin/users/{private_email}/drawer")
    client.post("/api/go-ghost/removals/people", json={})
    for number in range(25):
        assert client.get(f"/missing-metrics-test/{number}").status_code == 404
    client.request("UNUSUAL", "/health")

    assert {labels["path"] for labels in requests.label_sets} == {
        "/admin/users/{email}/drawer", "/api/go-ghost/removals/{broker}", "unmatched", "/health"
    }
    assert {labels["path"] for labels in latencies.label_sets} == {
        labels["path"] for labels in requests.label_sets
    }
    assert sum(labels["path"] == "unmatched" and labels["status"] == "404"
               for labels in requests.label_sets) == 25
    assert any(labels["method"] == "OTHER" for labels in requests.label_sets)
    assert private_email not in str(requests.label_sets)


def test_provider_health_reports_status_without_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "legacy-secret-value")
    monkeypatch.delenv("SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret-value")
    monkeypatch.setenv("SAFESCAN_VIRUSTOTAL_LICENSED", "true")
    _, client, _ = load_app(tmp_path, monkeypatch)

    degraded = client.get("/health/providers")
    ready = client.get("/health/ready")

    assert degraded.status_code == 200
    assert degraded.json() == {"status": "incomplete"}
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
    assert configured.json() == {"status": "configured"}
    assert "web-risk-secret-value" not in configured.text
    assert "phish-test-key" not in configured.text


def test_production_schema_and_probe_details_are_private(tmp_path, monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    _, client, _ = load_app(tmp_path, monkeypatch)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404

    assert client.get("/health/ready").json() == {"status": "ready"}
    assert client.get("/health/providers").json() == {"status": "incomplete"}

    app_module = importlib.import_module("hackabull.app_module")

    def fail():
        raise RuntimeError("private database path and credential")

    monkeypatch.setattr(app_module, "database_path", fail)
    failed_ready = client.get("/health/ready")
    assert failed_ready.status_code == 503
    assert failed_ready.json()["status"] == "not_ready"
    assert failed_ready.json()["request_id"] == failed_ready.headers["X-Request-ID"]
    assert "private" not in failed_ready.text

    monkeypatch.setattr(app_module, "reputation_configuration", fail)
    failed_providers = client.get("/health/providers")
    assert failed_providers.status_code == 503
    assert failed_providers.json()["status"] == "unavailable"
    assert failed_providers.json()["request_id"] == failed_providers.headers["X-Request-ID"]
    assert "credential" not in failed_providers.text


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
