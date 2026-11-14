"""IP fraud signals survive a bounded transition away from raw IP storage."""

import importlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest
from starlette.requests import Request


RAW_IP = "203.0.113.19"
STRONG_SALT = "IpPrivacyTest_73a4cf91e8b2d6075f3c0a49"


def _request(ip=RAW_IP):
    return Request({"type": "http", "client": (ip, 4567), "headers": [], "method": "POST", "path": "/"})


@pytest.fixture()
def ip_registry(tmp_path, monkeypatch):
    db_path = tmp_path / "ip-registry.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("PRIVACY_HASH_SALT", STRONG_SALT)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("AIRDROP_ENABLED", "false")

    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    app = importlib.import_module("hackabull")
    yield app, db_path
    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)


def test_new_events_and_flags_store_hash_without_raw_ip(ip_registry):
    app, db_path = ip_registry
    for index in range(4):
        signals = app.run_fraud_checks("signup", f"account-{index}", request=_request())

    with sqlite3.connect(db_path) as conn:
        addresses = [row[0] for row in conn.execute("SELECT ip_address FROM ip_registry")]
        flags = [row[0] for row in conn.execute("SELECT metadata FROM fraud_flags")]
        aggregate = conn.execute("SELECT COUNT(*) FROM ip_registry_accounts").fetchone()[0]
    expected_hash = app.hash_ip(RAW_IP)
    assert addresses == [expected_hash] * 4
    assert aggregate == 4
    assert signals[0]["metadata"] == {"ipHash": expected_hash, "recentSignups": 4}
    assert flags and all(RAW_IP not in value for value in flags)
    assert all("ip" not in json.loads(value) for value in flags)


def test_legacy_recent_events_still_count_and_old_events_roll_into_aggregate(ip_registry):
    app, db_path = ip_registry
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    recent = (now - timedelta(minutes=30)).isoformat() + "Z"
    expired = (now - timedelta(days=31)).isoformat() + "Z"
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO ip_registry VALUES (?, ?, ?, 'signup', ?)",
            [(f"recent-{i}", RAW_IP, f"recent-account-{i}", recent) for i in range(3)]
            + [(f"expired-{i}", RAW_IP, f"expired-account-{i}", expired) for i in range(8)],
        )

    signals = app.run_fraud_checks("signup", "current-account", request=_request())
    assert signals[0]["checkName"] == "ip_clustering"
    assert signals[0]["severity"] == "critical"
    assert signals[0]["metadata"]["accountCount"] == 12
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ip_registry WHERE id LIKE 'expired-%'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM ip_registry_accounts").fetchone()[0] == 9
        assert conn.execute("SELECT COUNT(*) FROM ip_registry WHERE ip_address = ?", (RAW_IP,)).fetchone()[0] == 3


def test_legacy_recent_signups_count_without_double_counting_account(ip_registry):
    app, db_path = ip_registry
    recent = (datetime.utcnow() - timedelta(minutes=30)).isoformat() + "Z"
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO ip_registry VALUES (?, ?, ?, 'signup', ?)",
            [(f"legacy-{i}", RAW_IP, f"account-{i}", recent) for i in range(3)],
        )
    signals = app.run_fraud_checks("signup", "account-0", request=_request())
    assert signals[0]["severity"] == "high"
    assert signals[0]["metadata"]["recentSignups"] == 4
    assert "accountCount" not in signals[0]["metadata"]


def test_maintenance_is_bounded_and_scrubs_existing_flag_metadata(ip_registry):
    app, db_path = ip_registry
    expired = (datetime.utcnow() - timedelta(days=31)).isoformat() + "Z"
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO ip_registry VALUES (?, ?, ?, 'scan', ?)",
            [(f"old-{i}", RAW_IP, "same-account", expired) for i in range(3)],
        )
        conn.execute(
            "INSERT INTO fraud_flags (id, user_id, check_name, severity, reason, metadata, created_at) "
            "VALUES ('legacy-flag', 'same-account', 'ip_clustering', 'high', 'cluster', ?, ?)",
            (json.dumps({"ip": RAW_IP, "recentSignups": 4}), expired),
        )
        conn.execute(
            "INSERT INTO audit_logs (id, action, ip_address, created_at) VALUES ('old-audit', 'test', ?, ?)",
            (RAW_IP, expired),
        )
        conn.execute(
            "INSERT INTO audit_logs (id, action, ip_address, created_at) VALUES ('new-audit', 'test', ?, ?)",
            (RAW_IP, datetime.utcnow().isoformat() + "Z"),
        )
    assert app.maintain_ip_registry(batch_limit=2) == {"eventsDeleted": 2, "flagsRedacted": 1, "auditIpsCleared": 1}
    assert app.maintain_ip_registry(batch_limit=2) == {"eventsDeleted": 1, "flagsRedacted": 0, "auditIpsCleared": 0}
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ip_registry").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM ip_registry_accounts").fetchone()[0] == 1
        metadata = conn.execute("SELECT metadata FROM fraud_flags WHERE id='legacy-flag'").fetchone()[0]
        audit_values = dict(conn.execute("SELECT id, ip_address FROM audit_logs"))
    assert json.loads(metadata) == {"ipHash": app.hash_ip(RAW_IP), "recentSignups": 4}
    assert RAW_IP not in metadata
    assert audit_values == {"old-audit": None, "new-audit": RAW_IP}


def test_production_rejects_missing_or_placeholder_privacy_salt(ip_registry, monkeypatch):
    app, _ = ip_registry
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("PRIVACY_HASH_SALT")
    with pytest.raises(RuntimeError, match="PRIVACY_HASH_SALT"):
        app.init_db()
    monkeypatch.setenv("PRIVACY_HASH_SALT", "replace-with-random-privacy-salt")
    with pytest.raises(RuntimeError, match="PRIVACY_HASH_SALT"):
        app.hash_ip(RAW_IP)
    monkeypatch.setenv("PRIVACY_HASH_SALT", STRONG_SALT)
    assert len(app.hash_ip(RAW_IP)) == 64


def test_login_does_not_store_raw_ip_and_upgrade_clears_legacy_value(ip_registry):
    app, db_path = ip_registry
    app.save_user_to_db("local-account", "local@example.com", request=_request())
    app.save_federated_user_to_db(
        "google", "https://accounts.google.com", "unique-subject",
        "federated@example.com", request=_request(),
    )
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE login_ip IS NOT NULL").fetchone()[0] == 0
        conn.execute("UPDATE users SET login_ip = ? WHERE google_id = 'local-account'", (RAW_IP,))
    app.init_db()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE login_ip IS NOT NULL").fetchone()[0] == 0
