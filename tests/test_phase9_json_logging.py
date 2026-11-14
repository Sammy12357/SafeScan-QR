"""Request IDs and JSON logs must not reflect sensitive request material."""

import importlib
import json
import re
import sys
import types

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def logging_site(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'logging.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    yield app
    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def _json_lines(capfd):
    output = capfd.readouterr().out
    return output, [json.loads(line) for line in output.splitlines() if line.strip()]


def test_server_generated_request_id_ignores_client_header_and_redacts_url(logging_site, capfd):
    client = TestClient(logging_site.qr_app, base_url="https://testserver")
    supplied_id = "attacker-token-" + "x" * 1000
    first = client.get(
        "/api/health?qr=https://private.example/pay?token=SECRET-QR-TOKEN",
        headers={"X-Request-Id": supplied_id, "X-Forwarded-For": "198.51.100.77"},
    )
    second = client.get("/api/health")
    first_id = first.headers["x-request-id"]
    second_id = second.headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", first_id)
    assert re.fullmatch(r"[0-9a-f]{32}", second_id)
    assert first_id != second_id
    assert first_id != supplied_id

    output, events = _json_lines(capfd)
    assert len(events) == 2
    assert {event["request_id"] for event in events} == {first_id, second_id}
    assert all(event["event"] == "request.completed" for event in events)
    assert all(event["route"] == "/api/health" and event["status"] == 200 for event in events)
    for secret in ("SECRET-QR-TOKEN", "private.example", "198.51.100.77", supplied_id):
        assert secret not in output


def test_early_body_reject_and_cors_preflight_have_request_ids(logging_site, capfd):
    client = TestClient(logging_site.qr_app, base_url="https://testserver")
    oversized = client.post("/api/analyze", content=b"{" + b"x" * (65 * 1024), headers={"Content-Type": "application/json"})
    preflight = client.options(
        "/api/health",
        headers={"Origin": "https://untrusted.example", "Access-Control-Request-Method": "GET"},
    )
    assert oversized.status_code == 413
    assert preflight.status_code == 400
    assert re.fullmatch(r"[0-9a-f]{32}", oversized.headers["x-request-id"])
    assert re.fullmatch(r"[0-9a-f]{32}", preflight.headers["x-request-id"])
    output, events = _json_lines(capfd)
    assert {event["status"] for event in events} == {400, 413}
    assert "untrusted.example" not in output


def test_unhandled_exception_returns_generic_500_and_logs_only_type(logging_site, capfd):
    @logging_site.qr_app.get("/test/fail/{item}")
    async def failed(item: str):
        raise RuntimeError("QR_SECRET https://private.example/?token=TOPSECRET 203.0.113.9")

    client = TestClient(logging_site.qr_app, base_url="https://testserver", raise_server_exceptions=False)
    response = client.get("/test/fail/customer-qr?token=QUERYSECRET")
    request_id = response.headers["x-request-id"]
    assert response.status_code == 500
    assert response.json() == {"error": "Something went wrong on our end."}
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert re.fullmatch(r"[0-9a-f]{32}", request_id)

    output, events = _json_lines(capfd)
    assert {event["event"] for event in events} == {"request.exception", "request.completed"}
    error = next(event for event in events if event["event"] == "request.exception")
    assert error["request_id"] == request_id
    assert error["error_type"] == "RuntimeError"
    assert error["route"] == "/test/fail/{item}"
    assert all(event["request_id"] == request_id for event in events)
    for secret in ("QR_SECRET", "TOPSECRET", "QUERYSECRET", "private.example", "203.0.113.9", "customer-qr"):
        assert secret not in output


def test_logger_replaces_untrusted_field_values_with_bounded_categories(logging_site, capfd):
    from hackabull.observability import log_event

    log_event(
        "malicious\nentry", level="attacker", request_id="bad\nrequest-id",
        method="POST\nFAKE", route="/scan?token=SECRET\nFAKE", error_type="Bad\nError",
        status_code=9999, duration_ms=99999999,
    )
    output, events = _json_lines(capfd)
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "invalid_event"
    assert event["level"] == "warning"
    assert event["method"] == "OTHER"
    assert event["route"] == "unmatched"
    assert event["error_type"] == "Exception"
    assert event["duration_ms"] == 600000
    assert "request_id" not in event and "status" not in event
    assert "SECRET" not in output and "FAKE" not in output


def test_model_failure_logs_no_exception_message_or_url(logging_site, monkeypatch, tmp_path, capfd):
    model = importlib.import_module("ml_model_final")
    artifact = tmp_path / "classifier.joblib"
    artifact.write_bytes(b"invalid")
    monkeypatch.setattr(model, "URL_CLASSIFIER_PATH", str(artifact))
    monkeypatch.setattr(model, "_url_classifier", None)
    monkeypatch.setattr(model, "_url_classifier_missing", False)
    joblib = types.ModuleType("joblib")
    monkeypatch.setitem(sys.modules, "joblib", joblib)

    def fail_load(_):
        raise RuntimeError("load SECRET_MODEL_TOKEN https://private.example/qr")

    monkeypatch.setattr(joblib, "load", fail_load, raising=False)
    assert model._load_url_classifier() is None
    output, events = _json_lines(capfd)
    assert any(event["event"] == "ml.classifier_load_failed" for event in events)
    assert "SECRET_MODEL_TOKEN" not in output
    assert "private.example" not in output
