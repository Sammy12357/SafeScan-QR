"""The diagnostic endpoint accepts only anonymous, bounded count fields."""

import importlib
import json
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient


def load_app(tmp_path, monkeypatch, scanner_v3=False):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'telemetry.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SCANNER_V3", "true" if scanner_v3 else "false")
    monkeypatch.setenv("METRICS_TOKEN", "test-metrics-bearer-secret-32-characters")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage", "safescan_model_calibration"} or name.startswith(("hackabull.", "safescan_model_calibration.")):
            sys.modules.pop(name, None)
    module = importlib.import_module("hackabull")
    telemetry = sys.modules["hackabull.routes_scan_telemetry"]
    telemetry._recent_events.clear()
    return module, telemetry, TestClient(module.qr_app, base_url="https://testserver", client=("127.0.0.1", 50000))


def sample_event():
    return {"engine": "wasm", "stage": "capture", "frames_tried": 6, "ms": 450,
            "outcome": "success", "guidance_shown": ["small", "ready"]}


def test_rollback_camera_keeps_the_self_hosted_reader():
    legacy = (Path(__file__).resolve().parents[1] / "static" / "qr-camera-phase3.js").read_text()
    assert 'new Worker(WORKER_URL)' in legacy
    assert '/static/qr-worker.js?v=scanner-phase-2b' in legacy
    assert 'jsdelivr' not in legacy


def test_counts_only_endpoint_and_rollout_flag(tmp_path, monkeypatch):
    module, _, client = load_app(tmp_path, monkeypatch)
    assert module.SCANNER_V3 is False
    home = client.get("/")
    assert home.status_code == 200
    assert 'qr-camera-phase3.js?v=scanner-phase-3-simplified-controls' in home.text
    assert 'src="/static/qr-camera.js?v=scanner-v3-simplified-controls"' not in home.text
    counted = client.post("/api/telemetry/scan", json=sample_event())
    assert counted.status_code == 204
    assert counted.headers["cache-control"] == "no-store"
    metrics = client.get("/metrics", headers={"Authorization": "Bearer test-metrics-bearer-secret-32-characters"})
    assert metrics.status_code == 200
    assert b"safescan_scanner_events_total" in metrics.content or b"prometheus-client is not installed" in metrics.content

    module, _, client = load_app(tmp_path, monkeypatch, scanner_v3=True)
    assert module.SCANNER_V3 is True
    home = client.get("/")
    assert 'src="/static/qr-camera.js?v=scanner-v3-simplified-controls"' in home.text
    assert 'qr-camera-phase3.js?v=scanner-phase-3-simplified-controls' not in home.text


def test_payloads_images_identifiers_and_unbounded_events_are_rejected(tmp_path, monkeypatch):
    _, telemetry, client = load_app(tmp_path, monkeypatch)
    event = sample_event()
    for unexpected in ({"payload": "https://private.example"}, {"device_id": "camera-1"}, {"image": "base64..."}, {"ip": "127.0.0.1"}):
        response = client.post("/api/telemetry/scan", json={**event, **unexpected})
        assert response.status_code == 400
        assert "private.example" not in response.text
    assert client.post("/api/telemetry/scan", json={**event, "guidance_shown": ["raw message"]}).status_code == 400
    assert client.post("/api/telemetry/scan", json={**event, "frames_tried": True}).status_code == 400
    assert client.post("/api/telemetry/scan", json={**event, "ms": 10 ** 300}).status_code == 400
    assert client.post("/api/telemetry/scan", content=json.dumps(event).encode() + b" " * 600,
                       headers={"content-type": "application/json"}).status_code == 413
    assert len(telemetry._recent_events) == 0


def test_rate_budget_only_drops_telemetry_not_scans(tmp_path, monkeypatch):
    module, telemetry, client = load_app(tmp_path, monkeypatch)
    telemetry._recent_events.extend([time.monotonic()] * telemetry.EVENT_LIMIT_PER_MINUTE)
    blocked = client.post("/api/telemetry/scan", json=sample_event())
    assert blocked.status_code == 429
    assert blocked.headers["cache-control"] == "no-store"
    assert module.RATE_LIMITS == {}, "generic IP-linked audit limiter must not process telemetry"
    assert client.get("/health").status_code == 200
    assert client.post("/search_qr_api", data={"manual_url": "WIFI:T:WPA;S:Test;P:test;;"}).status_code == 200
