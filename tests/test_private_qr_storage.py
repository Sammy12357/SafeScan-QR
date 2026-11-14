"""Private QR data must stay in the one-time scan response, not persistent state."""

import importlib
import asyncio
import hashlib
import io
import json
import sqlite3
import sys
import time
from html import escape

import qrcode
from browser_client import BrowserTestClient as TestClient


def load_app(tmp_path, monkeypatch):
    db_path = tmp_path / "private-scans.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "test-key-for-qr-fingerprints-only")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage", "safescan_model_calibration"} or name.startswith(("hackabull.", "safescan_model_calibration.")):
            sys.modules.pop(name, None)
    module = importlib.import_module("hackabull")
    module.RATE_LIMITS.clear()
    return module, TestClient(module.qr_app, base_url="https://testserver"), db_path


def rows(db_path, table):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]


def assert_secret_absent_from_disk(tmp_path, secret):
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), path


def qr_png(payload):
    result = io.BytesIO()
    qrcode.make(payload).save(result, format="PNG")
    return result.getvalue()


def test_guest_uploaded_authenticator_secret_is_not_retained(tmp_path, monkeypatch):
    _, client, db_path = load_app(tmp_path, monkeypatch)
    secret = "JBSWY3DPEHPK3PXP"
    payload = f"otpauth://totp/Example:alice?secret={secret}&issuer=Example"

    response = client.post("/search_qr_api", files={"file": ("auth.png", qr_png(payload), "image/png")})

    assert response.status_code == 200
    assert secret in response.text  # The scanner still shows this user their decoded QR.
    assert response.headers["cache-control"] == "private, no-store"
    assert rows(db_path, "upload_artifacts") == []
    assert rows(db_path, "scan_history") == []
    assert_secret_absent_from_disk(tmp_path, secret)


def test_guest_camera_frame_is_decoded_without_retaining_image(tmp_path, monkeypatch):
    _, client, db_path = load_app(tmp_path, monkeypatch)
    secret = "CAMERA_GUEST_TOTP_2946"
    payload = f"otpauth://totp/Example:guest?secret={secret}&issuer=Example"

    response = client.post(
        "/search_qr_api",
        data={"capture_source": "camera_frame"},
        files={"file": ("camera.jpg", qr_png(payload), "image/jpeg")},
    )

    assert response.status_code == 200
    assert secret in response.text
    assert response.headers["cache-control"] == "private, no-store"
    assert rows(db_path, "upload_artifacts") == []
    assert rows(db_path, "scan_history") == []
    assert_secret_absent_from_disk(tmp_path, secret)


def test_large_camera_frame_stays_in_memory_without_temp_spool(tmp_path, monkeypatch):
    _, client, db_path = load_app(tmp_path, monkeypatch)
    import starlette.formparsers as formparsers

    def reject_spool(_self):
        raise AssertionError("QR camera frame spilled to disk")

    monkeypatch.setattr(formparsers.SpooledTemporaryFile, "rollover", reject_spool)
    # The decoder is irrelevant to this parser/storage check. A 1.5 MiB
    # frame crosses Starlette's old 1 MiB disk-spool threshold.
    route = sys.modules["hackabull.routes_scan_auth"]
    monkeypatch.setattr(route, "decode_qr_upload", lambda *_args: ("WIFI:T:WPA;S:Cafe;P:camera-test;;", None))
    frame = b"camera-test-frame" + b"x" * (1_500_000 - len("camera-test-frame"))
    response = client.post(
        "/search_qr_api",
        data={"capture_source": "camera_frame"},
        files={"file": ("camera.jpg", frame, "image/jpeg")},
    )

    assert response.status_code == 200
    assert rows(db_path, "upload_artifacts") == []


def test_camera_upload_bounds_and_client_budget_cannot_use_forged_xff(tmp_path, monkeypatch):
    module, client, _ = load_app(tmp_path, monkeypatch)
    app_module = sys.modules["hackabull.app_module"]
    too_large = client.post(
        "/search_qr_api",
        content=b"x" * (app_module.QR_REQUEST_BODY_LIMIT + 1),
        headers={"content-type": "application/octet-stream"},
    )
    assert too_large.status_code == 413
    assert too_large.headers["cache-control"] == "no-store"

    streamed = client.post(
        "/search_qr_api",
        content=(b"x" * 500_000 for _ in range(18)),
        headers={"content-type": "application/octet-stream"},
    )
    assert streamed.status_code == 413

    # TestClient's default "testclient" peer is not an IP literal. Use a real
    # socket-style peer so this checks the same identity path as production.
    primary = TestClient(module.qr_app, base_url="https://testserver", client=("198.51.100.10", 50000))
    module.RATE_LIMITS["qr_upload_client:198.51.100.10"] = [time.time()] * 90
    blocked = primary.post(
        "/search_qr_api",
        data={"manual_url": "WIFI:T:WPA;S:Cafe;P:test;;"},
        headers={"x-forwarded-for": "198.51.100.77", "cf-connecting-ip": "198.51.100.88"},
    )
    assert blocked.status_code == 429
    assert blocked.headers["cache-control"] == "no-store"
    assert "qr_upload_global:all" not in module.RATE_LIMITS

    # A second visitor is not locked out by the first visitor's budget.
    other = TestClient(module.qr_app, base_url="https://testserver", client=("198.51.100.89", 50000))
    allowed = other.post("/search_qr_api", data={"manual_url": "WIFI:T:WPA;S:Other;P:test;;"})
    assert allowed.status_code == 200


def test_slow_camera_body_releases_upload_slot(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from starlette.requests import Request

    app_module = sys.modules["hackabull.app_module"]
    monkeypatch.setattr(app_module, "QR_REQUEST_READ_TIMEOUT_SECONDS", 0.01)

    async def run():
        async def slow_receive():
            await asyncio.sleep(0.05)
            return {"type": "http.request", "body": b"", "more_body": False}

        request = Request({
            "type": "http", "method": "POST", "path": "/search_qr_api",
            "headers": [], "client": ("198.51.100.90", 50000),
            "scheme": "https", "server": ("testserver", 443),
        }, receive=slow_receive)

        async def never_called(_request):
            raise AssertionError("slow body reached the scan route")

        return await app_module.security_headers_and_rate_limits(request, never_called)

    response = asyncio.run(run())
    assert response.status_code == 408
    assert response.headers["cache-control"] == "no-store"
    assert app_module.QR_REQUEST_ACTIVE_BY_CLIENT == {}


def test_camera_source_requires_a_file(tmp_path, monkeypatch):
    _, client, _ = load_app(tmp_path, monkeypatch)
    response = client.post("/search_qr_api", data={"capture_source": "camera_frame"})
    assert response.status_code == 400


def test_manual_qr_payload_is_bounded_like_api_scans(tmp_path, monkeypatch):
    _, client, _ = load_app(tmp_path, monkeypatch)
    response = client.post("/search_qr_api", data={"manual_url": "A" * 4097})
    assert response.status_code == 400
    assert "too large" in response.text.lower()


def test_ml_cache_rejects_private_qr_keys(tmp_path, monkeypatch):
    _, _, _ = load_app(tmp_path, monkeypatch)
    cache = importlib.import_module("safescan_model_calibration.cache")
    private_payload = "otpauth://totp/Test?secret=NeverCacheThisSeed"

    cache.cache_put(private_payload, {"enabled": True})

    assert cache.cache_get(private_payload) is None
    assert not (tmp_path / "ml_cache.sqlite").exists()
    assert_secret_absent_from_disk(tmp_path, "NeverCacheThisSeed")


def test_weak_fingerprint_keys_are_ignored(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    privacy = importlib.import_module("hackabull.payload_privacy")
    monkeypatch.setattr(privacy, "_PROCESS_FINGERPRINT_KEY", b"p" * 32)
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "too-short")
    monkeypatch.setenv("AIRDROP_ADMIN_SECRET", "also-short")
    payload = "WIFI:T:WPA;S:Example;P:private-password;;"

    first = privacy.scan_storage_reference(payload, "user-1", "Wi-Fi")
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "a-different-short-key")
    second = privacy.scan_storage_reference(payload, "user-1", "Wi-Fi")
    monkeypatch.setenv("AIRDROP_ADMIN_SECRET", "s" * 32)
    with_strong_fallback = privacy.scan_storage_reference(payload, "user-1", "Wi-Fi")

    assert first == second
    assert with_strong_fallback != first
    assert "private-password" not in first


def test_authenticated_wifi_upload_keeps_counts_but_not_password_or_image(tmp_path, monkeypatch):
    module, client, db_path = load_app(tmp_path, monkeypatch)
    assert client.post("/auth/register", data={"email": "alice@example.com", "password": "password123"}).status_code == 200
    password = "secret-https://attacker.example/drain"
    payload = f"WIFI:T:WPA;S:Cafe;P:{password};;"

    def unexpected_network_analysis(*_args, **_kwargs):
        raise AssertionError("non-URL QR content must not be sent to URL reputation or redirect checks")

    sys.modules["hackabull.routes_scan_auth"].analyze_full_pipeline = unexpected_network_analysis
    response = client.post("/search_qr_api", files={"file": ("wifi.png", qr_png(payload), "image/png")})

    assert response.status_code == 200
    assert password in response.text
    assert response.headers["cache-control"] == "private, no-store"
    assert "Embedded links not fetched" in response.text
    assert module.get_scan_count("alice@example.com") == 1
    assert rows(db_path, "upload_artifacts") == []
    assert len(rows(db_path, "scan_history")) == 1
    assert rows(db_path, "scan_history")[0]["url"].startswith("[Wi-Fi QR payload redacted;")
    assert rows(db_path, "scan_history")[0]["risk_score"] >= 70
    assert "QR payload redacted" in rows(db_path, "scans")[0]["url_found"]
    assert rows(db_path, "scan_velocity")[0]["last_scan_url"].startswith("[Wi-Fi QR payload redacted;")
    assert_secret_absent_from_disk(tmp_path, password)


def test_authenticated_api_file_scan_returns_secret_only_to_scanner(tmp_path, monkeypatch):
    _, client, db_path = load_app(tmp_path, monkeypatch)
    assert client.post("/auth/register", data={"email": "alice@example.com", "password": "password123"}).status_code == 200
    secret = "API_FILE_TOTP_SEED_654321"
    payload = f"otpauth://totp/Example:alice?secret={secret}&issuer=Example"

    result = client.post("/api/scan/file", files={"file": ("totp.png", qr_png(payload), "image/png")})

    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    assert result.json()["rawPayload"] == payload
    assert rows(db_path, "upload_artifacts") == []
    assert rows(db_path, "scan_history")[0]["url"].startswith("[Authentication QR payload redacted;")
    assert_secret_absent_from_disk(tmp_path, secret)


def test_manual_and_api_private_scans_dedupe_without_exposing_payload(tmp_path, monkeypatch):
    module, client, db_path = load_app(tmp_path, monkeypatch)
    assert client.post("/auth/register", data={"email": "alice@example.com", "password": "password123"}).status_code == 200
    first = "wc:pairing@2?relay-protocol=irn&symKey=VeryPrivatePairingKey123"
    second = "wc:pairing@2?relay-protocol=irn&symKey=AnotherPrivatePairingKey456"

    html = client.post("/search_qr_api", data={"manual_url": first})
    api_first = client.post("/api/scan", json={"payload": first})
    api_second = client.post("/api/scan", json={"payload": second})

    assert html.status_code == api_first.status_code == api_second.status_code == 200
    assert html.headers["cache-control"] == "private, no-store"
    assert api_first.headers["cache-control"] == "no-store"
    assert escape(first) in html.text
    assert api_first.json()["rawPayload"] == first
    assert module.get_scan_count("alice@example.com") == 2
    assert len(rows(db_path, "scan_events")) == 2
    assert all(row["url_found"].startswith("[Crypto/payment QR payload redacted;") for row in rows(db_path, "scan_events"))
    assert len({row["url_found"] for row in rows(db_path, "scan_events")}) == 2
    assert hashlib.sha256(first.encode()).hexdigest() not in {row["payload_hash"] for row in rows(db_path, "scan_events")}
    history = client.get("/api/scan-history").json()
    scans = client.get("/api/scans").json()
    assert all("QR payload redacted" in row["url"] for row in history)
    assert all("payload_hash" not in row for row in scans["events"])
    assert first not in json.dumps((history, scans))
    assert second not in json.dumps((history, scans))
    assert_secret_absent_from_disk(tmp_path, "VeryPrivatePairingKey123")
    assert_secret_absent_from_disk(tmp_path, "AnotherPrivatePairingKey456")


def test_legacy_private_history_is_hidden_in_normal_api_and_admin_data(tmp_path, monkeypatch):
    module, client, db_path = load_app(tmp_path, monkeypatch)
    assert client.post("/auth/register", data={"email": "alice@example.com", "password": "password123"}).status_code == 200
    secret = "LEGACY_OTP_SEED_123"
    raw = f"otpauth://totp/Alice?secret={secret}"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, classification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("legacy", "alice@example.com", raw, 95, "MALICIOUS", json.dumps([{"label": "Secret", "severity": "high", "detail": raw}]), 0, "2026-10-30T00:00:00Z", "MALICIOUS"),
        )
        conn.execute("INSERT INTO scan_events (email, payload_hash, url_found, first_scanned_at) VALUES (?, ?, ?, ?)", ("alice@example.com", "legacy-guessable-hash", raw, "2026-10-30T00:00:00Z"))
        conn.execute("INSERT INTO scans (email, url_found, scan_count) VALUES (?, ?, ?)", ("alice@example.com", raw, 1))
        conn.execute("INSERT INTO url_blocklist VALUES (?, ?, ?, ?, ?, NULL)", ("legacy-block", raw, "legacy entry", "admin@example.com", "2026-10-30T00:00:00Z"))

    history = client.get("/api/scan-history").json()
    scans = client.get("/api/scans").json()
    public_threats = client.get("/api/malicious-qr").json()
    threat_image = client.get("/api/malicious-qr/image", params={"u": raw})
    admin_record = module.safe_scan_history_record(rows(db_path, "scan_history")[0])
    admin_data = importlib.import_module("hackabull.admin_data")
    admin_reports = admin_data.fetch_reports()
    admin_flag = admin_data.safe_fraud_flag_record({"metadata": json.dumps({"url": raw})})
    assert secret not in json.dumps((history, scans, public_threats, admin_record, admin_reports, admin_flag))
    assert history[0]["url"] == "[Non-URL QR payload redacted]"
    assert history[0]["signals"][0]["label"] == "Non-URL QR action"
    assert public_threats["entries"] == []
    assert threat_image.status_code == 404
    module.record_unique_scan("alice@example.com", "https://safe.example/", "")
    assert secret not in rows(db_path, "scans")[0]["url_found"]


def test_admin_fraud_flags_api_redacts_legacy_private_qr_metadata(tmp_path, monkeypatch):
    _, client, db_path = load_app(tmp_path, monkeypatch)
    assert client.post("/auth/register", data={"email": "admin@example.com", "password": "password123"}).status_code == 200
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE users SET role = 'admin' WHERE email = ?", ("admin@example.com",))
    secret = "LEGACY_OTP_SEED_IN_FRAUD_FLAG"
    private_payload = f"otpauth://totp/Alice?secret={secret}"
    web_url = "https://example.com/known-threat"
    with sqlite3.connect(db_path) as conn:
        for flag_id, url in (("private", private_payload), ("web", web_url)):
            conn.execute(
                "INSERT INTO fraud_flags (id, user_id, check_name, severity, reason, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (flag_id, "alice@example.com", "duplicate_url_scans", "medium", "Repeated scan", json.dumps({"url": url, "duplicateCount": 4}), "2026-10-30T00:00:00Z"),
            )

    response = client.get("/api/fraud-flags")

    assert response.status_code == 200
    assert secret not in response.text
    records = {row["id"]: row for row in response.json()["rows"]}
    assert json.loads(records["private"]["metadata"])["url"] == "[Non-URL QR payload redacted]"
    assert json.loads(records["web"]["metadata"])["url"] == web_url
