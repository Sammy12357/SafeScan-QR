"""Per-field limits prevent oversized text from reaching storage or scanners."""

import importlib
import sqlite3
import sys

import pytest

from browser_client import BrowserTestClient


@pytest.fixture()
def field_app(tmp_path, monkeypatch):
    db_path = tmp_path / "fields.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    yield BrowserTestClient(app.qr_app, base_url="https://testserver"), db_path, monkeypatch
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _rows(db_path, table):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


@pytest.mark.parametrize("field,invalid", [
    ("email", "e" * 255),
    ("region", "r" * 121),
    ("request_type", "x" * 41),
    ("request_type", "unknown"),
    ("details", "d" * 4001),
])
def test_data_request_rejects_bad_fields_before_writing(field_app, field, invalid):
    client, db_path, _ = field_app
    form = {"email": "person@example.com", "region": "Canada", "request_type": "access", "details": "Please export."}
    form[field] = invalid

    response = client.post("/legal/data-request", data=form)

    assert response.status_code == 400
    assert _rows(db_path, "data_requests") == 0
    assert _rows(db_path, "privacy_opt_outs") == 0


def test_data_request_accepts_full_length_details_without_truncation(field_app):
    client, db_path, _ = field_app
    details = "D" * 4000

    response = client.post("/legal/data-request", data={
        "email": "person@example.com", "region": "C" * 120,
        "request_type": "rectification", "details": details,
    })

    assert response.status_code == 200
    with sqlite3.connect(db_path) as conn:
        stored = conn.execute("SELECT region, details FROM data_requests").fetchone()
    assert stored == ("C" * 120, details)


def test_waitlist_rejects_long_email_before_rate_keys_or_storage(field_app):
    client, db_path, _ = field_app

    assert client.post("/waitlist", data={"email": "a" * 255}).status_code == 400
    assert _rows(db_path, "waitlist_signups") == 0
    assert client.post("/waitlist", data={"email": " Person@Example.com "}).status_code == 200
    with sqlite3.connect(db_path) as conn:
        stored = conn.execute("SELECT email FROM waitlist_signups").fetchone()[0]
    assert stored == "person@example.com"


@pytest.mark.parametrize("field,invalid", [
    ("name", ["Person"]),
    ("name", "N" * 161),
    ("address", {"street": "Main"}),
    ("address", "A" * 221),
    ("cityState", "C" * 141),
    ("phone", 1234567890),
    ("phone", "P" * 81),
    ("email", True),
    ("email", "E" * 255),
])
def test_go_ghost_rejects_bad_profile_before_job_or_browser(field_app, field, invalid):
    client, db_path, monkeypatch = field_app
    pages = importlib.import_module("hackabull.routes_pages")
    import removals.engine as engine

    monkeypatch.setattr(pages, "require_user", lambda request: {"google_id": "person", "email": "person@example.com"})
    monkeypatch.setattr(engine, "supported_broker", lambda broker: type("Broker", (), {"optout_url": "https://example.com", "name": "Example"})())

    async def should_not_run(*_args):
        pytest.fail("browser automation must not run for invalid profile data")

    monkeypatch.setattr(engine, "run_broker_removal", should_not_run)
    profile = {"name": "Person", "address": "123 Main", "cityState": "Toronto, ON", "phone": "555-1212", "email": "person@example.com"}
    profile[field] = invalid

    response = client.post("/api/go-ghost/removals/example", json=profile)

    assert response.status_code == 400
    assert _rows(db_path, "go_ghost_removal_jobs") == 0


def test_go_ghost_accepts_fields_at_existing_caps(field_app):
    client, db_path, monkeypatch = field_app
    pages = importlib.import_module("hackabull.routes_pages")
    import removals.engine as engine

    monkeypatch.setattr(pages, "require_user", lambda request: {"google_id": "person", "email": "person@example.com"})
    monkeypatch.setattr(engine, "supported_broker", lambda broker: type("Broker", (), {"optout_url": "https://example.com", "name": "Example"})())
    seen = []

    async def done(_broker, profile):
        seen.append(profile)
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    email = "E" * (254 - len("@example.com")) + "@example.com"
    profile = {"name": "N" * 160, "address": "A" * 220, "cityState": "C" * 140, "phone": "P" * 80, "email": email, "delegateAttestation": True}

    response = client.post("/api/go-ghost/removals/example", json=profile)

    assert response.status_code == 200
    assert _rows(db_path, "go_ghost_removal_jobs") == 1
    assert seen[0].name == profile["name"]
    assert seen[0].address == profile["address"]
    assert seen[0].city_state == profile["cityState"]
    assert seen[0].email == email


@pytest.mark.parametrize("path,body", [
    ("/api/analyze", {"url": ["https://example.com"]}),
    ("/api/qr/generate", {"url": {"value": "https://example.com"}}),
    ("/api/report", {"url": "https://example.com", "reason": ["phishing"]}),
    ("/api/report", {"url": "https://example.com", "reason": "x" * 1000}),
    ("/api/check-reputation", {"url": ["https://example.com"]}),
])
def test_public_url_and_report_types_reject_before_external_checks(field_app, path, body):
    client, db_path, monkeypatch = field_app
    api = importlib.import_module("hackabull.routes_api")

    async def should_not_analyze(*_args):
        pytest.fail("scanner must not run for invalid input")

    monkeypatch.setattr(api, "analyze_full_pipeline", should_not_analyze)
    response = client.post(path, json=body)

    assert response.status_code == 400
    assert _rows(db_path, "url_reports") == 0


def test_scan_text_is_bounded_before_payload_analysis(field_app):
    client, _, monkeypatch = field_app
    scan = importlib.import_module("hackabull.routes_scan_auth")

    def should_not_decode(*_args):
        pytest.fail("QR parser must not run for oversized manual text")

    monkeypatch.setattr(scan, "detect_payload", should_not_decode)
    response = client.post("/search_qr_api", data={"manual_url": "A" * 4097})
    assert response.status_code == 400


@pytest.mark.parametrize("payload", [["WIFI:T:WPA;S:Cafe;;"], "Q" * 4097])
def test_user_scan_rejects_invalid_or_oversized_text_before_recording(field_app, payload):
    client, db_path, monkeypatch = field_app
    api = importlib.import_module("hackabull.routes_api")
    monkeypatch.setattr(api, "require_user", lambda request: {"google_id": "person", "email": "person@example.com"})

    async def should_not_analyze(*_args):
        pytest.fail("scanner must not run for invalid payload text")

    monkeypatch.setattr(api, "analyze_and_record_scan", should_not_analyze)
    response = client.post("/api/scan", json={"payload": payload})

    assert response.status_code == 400
    assert _rows(db_path, "scans") == 0
