"""Live-main regression tests for ambiguous legacy account ownership."""

from concurrent.futures import ThreadPoolExecutor
import importlib
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def live_app(tmp_path, monkeypatch):
    database = tmp_path / "live-hotfix.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.delenv("RENDER", raising=False)
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(routes, "LOCAL_AUTH_ENABLED", True)
    app.RATE_LIMITS.clear()
    yield app, database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _rows(database, sql, params=()):
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, params)]


def _register(app, database, email):
    client = TestClient(app.qr_app, base_url="https://testserver")
    response = client.post("/auth/register", data={"email": email, "password": "password123"})
    assert response.status_code == 200
    user_id = _rows(database, "SELECT google_id FROM users WHERE email = ?", (email,))[0]["google_id"]
    return client, user_id


def _seed_scans(database, email, first_id, second_id):
    with sqlite3.connect(database) as conn:
        for label, owner in (("first", first_id), ("second", second_id), ("legacy", None)):
            conn.execute(
                "INSERT INTO scan_history (id, email, url, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                (label, email, f"https://{label}.example", "2026-11-14T00:00:00Z", owner),
            )
            conn.execute(
                "INSERT INTO scan_events (email, payload_hash, url_found, first_scanned_at, user_id) VALUES (?, ?, ?, ?, ?)",
                (email, label, f"https://{label}.example", "2026-11-14T00:00:00Z", owner),
            )
        conn.execute(
            "INSERT INTO scans (email, url_found, scan_count, user_id) VALUES (?, ?, ?, ?)",
            (email, "[Scan payload list hidden]", 3, first_id),
        )


def test_collision_withholds_even_backfilled_id_rows_from_both_sessions(live_app, caplog):
    app, database = live_app
    first, first_id = _register(app, database, "shared@example.com")
    second, second_id = _register(app, database, "other@example.com")
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET email = ? WHERE google_id = ?", ("SHARED@example.com", second_id))
    _seed_scans(database, "shared@example.com", first_id, second_id)
    app.init_db()
    assert _rows(database, "SELECT user_id FROM scan_history WHERE id = 'legacy'") == [{"user_id": None}]

    for client in (first, second):
        assert client.get("/api/history").json() == []
        assert client.get("/api/scan-history").json() == []
        assert client.get("/api/scans").json() == {"scans": [], "events": []}
        profile = client.get("/api/user/profile").json()
        assert profile["scanCount"] == 0
        assert profile["walletConnected"] is False
        assert client.get("/api/referral").status_code == 409
        assert client.get("/api/airdrop/status").status_code == 409
        assert client.get("/api/wallet").status_code == 409

    assert all("shared@example.com" not in record.message.lower() for record in caplog.records)
    assert any("Withheld" in record.message for record in caplog.records)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result = pool.submit(lambda: first.get("/api/history").json())
        second_result = pool.submit(lambda: second.get("/api/history").json())
        assert first_result.result() == second_result.result() == []

    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'admin' WHERE google_id = ?", (first_id,))
    assert len(first.get("/api/history").json()) == 3

    db = importlib.import_module("db")
    with db.get_conn() as conn:
        token = db.set_rls_context(first_id, "user", "shared@example.com")
        try:
            with pytest.raises(PermissionError):
                db.assert_owns_row(conn, "scan_history", "first")
        finally:
            db.reset_rls_context(token)
        token = db.set_rls_context(first_id, "admin", "shared@example.com")
        try:
            assert len(db.user_scoped_select(conn, "scan_history")) == 3
            db.assert_owns_row(conn, "scan_history", "second")
        finally:
            db.reset_rls_context(token)


@pytest.mark.parametrize("request_type", ["access", "portability", "erasure"])
def test_collision_privacy_request_stays_pending_without_export_or_delete(live_app, request_type):
    app, database = live_app
    first, first_id = _register(app, database, "shared@example.com")
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("second-id", "SHARED@example.com"))
    _seed_scans(database, "shared@example.com", first_id, "second-id")

    response = first.post("/legal/data-request", data={"email": "shared@example.com", "request_type": request_type})

    assert response.status_code == 200
    assert "https://first.example" not in response.text
    assert "https://second.example" not in response.text
    assert _rows(database, "SELECT status FROM data_requests WHERE request_type = ?", (request_type,)) == [{"status": "submitted"}]
    assert len(_rows(database, "SELECT google_id FROM users")) == 2
    assert len(_rows(database, "SELECT id FROM scan_history")) == 3


def test_unique_owner_keeps_own_and_legacy_rows_but_not_foreign_id(live_app):
    app, database = live_app
    first, first_id = _register(app, database, "unique@example.com")
    _seed_scans(database, "unique@example.com", first_id, "unrelated-id")
    app.init_db()
    assert _rows(database, "SELECT user_id FROM scan_history WHERE id = 'legacy'") == [{"user_id": None}]
    assert {row["url"] for row in first.get("/api/history").json()} == {
        "https://first.example", "https://legacy.example",
    }
    scans = first.get("/api/scans").json()
    assert {row["user_id"] for row in scans["events"]} == {first_id, None}
    assert len(scans["scans"]) == 1
    export = importlib.import_module("hackabull.legal").get_user_export("unique@example.com", first_id)
    assert {row["payload_hash"] for row in export["scanEvents"]} == {"first", "legacy"}
    assert first.get("/api/user/profile").json()["scanCount"] == 3
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET user_id = 'unrelated-id' WHERE email = 'unique@example.com'")
    assert first.get("/api/user/profile").json()["scanCount"] == 0
    assert first.get("/api/scans").json()["scans"] == []
    erased = first.post("/legal/data-request", data={"email": "unique@example.com", "request_type": "erasure"})
    assert erased.status_code == 200
    assert _rows(database, "SELECT id FROM scan_history") == [{"id": "second"}]
    assert _rows(database, "SELECT payload_hash FROM scan_events") == [{"payload_hash": "second"}]
    assert _rows(database, "SELECT user_id FROM scans") == [{"user_id": "unrelated-id"}]


def test_canonical_unicode_and_idna_collisions_fail_closed(live_app):
    app, database = live_app
    _, first_id = _register(app, database, "foo@example.com")
    db = importlib.import_module("db")
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("unicode-id", "ＦＯＯ@example.com"))
    with db.get_conn() as conn:
        assert not db.unique_email_owner(conn, "foo@example.com", first_id)
        conn.execute("DELETE FROM users WHERE google_id = 'unicode-id'")
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("idna-id", "foo@bücher.example"))
        conn.execute("UPDATE users SET email = 'foo@xn--bcher-kva.example' WHERE google_id = ?", (first_id,))
        assert not db.unique_email_owner(conn, "foo@xn--bcher-kva.example", first_id)


def test_legacy_wallet_and_leaderboard_pause_on_collision(live_app):
    app, database = live_app
    first, first_id = _register(app, database, "shared@example.com")
    unique, unique_id = _register(app, database, "unique@example.com")
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("collision", "SHARED@example.com"))
        conn.execute("INSERT INTO wallets (id, user_id, address, connected_at) VALUES (?, ?, ?, ?)",
                     ("wallet-one", "shared@example.com", "private-wallet", "now"))
        conn.execute("INSERT INTO scan_history (id, email, url, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                     ("shared-scan", "shared@example.com", "https://shared.example", "now", first_id))
        conn.execute("INSERT INTO scan_history (id, email, url, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                     ("unique-scan", "unique@example.com", "https://unique.example", "now", unique_id))
    assert first.get("/api/wallet").status_code == 409
    assert first.delete("/api/wallet").status_code == 409
    assert _rows(database, "SELECT id FROM wallets") == [{"id": "wallet-one"}]
    assert [row["user_id"] for row in app.get_global_leaderboard()] == [unique_id]
    assert [row["url"] for row in unique.get("/api/history").json()] == ["https://unique.example"]


def test_unique_legacy_wallet_still_visible(live_app):
    app, database = live_app
    client, _ = _register(app, database, "unique@example.com")
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO wallets (id, user_id, address, connected_at) VALUES (?, ?, ?, ?)",
                     ("wallet-one", "unique@example.com", "normal-wallet", "now"))
    assert client.get("/api/wallet").json()["walletAddress"] == "normal-wallet"
