import importlib
import os
import sqlite3
import sys

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
    sys.modules.pop("hackabull", None)
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
