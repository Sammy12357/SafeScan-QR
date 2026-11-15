import importlib
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def security_app(tmp_path, monkeypatch):
    db_path = tmp_path / "security.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://safescan-qr.onrender.com,http://localhost:5173")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("OWNER_EMAILS", "owner@example.com")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")

    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
    module = importlib.import_module("hackabull")
    monkeypatch.setattr(importlib.import_module("hackabull.routes_scan_auth"), "LOCAL_AUTH_ENABLED", True)
    module.RATE_LIMITS.clear()
    module.run_fraud_checks = lambda *args, **kwargs: []

    yield module, TestClient(module.qr_app, base_url="https://testserver"), db_path

    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)


def register(client, email, password="password123"):
    return client.post("/auth/register", data={"email": email, "password": password}, follow_redirects=False)


def add_scan(db_path, email, url):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at)
            VALUES (?, ?, ?, 12, 'SAFE', '[]', 0, ?)
            """,
            (f"scan_{email.split('@')[0]}", email, url, f"2026-05-10T12:00:0{len(url) % 9}Z"),
        )


def test_security_headers_are_present_on_health_response(security_app):
    module, client, _ = security_app

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "frame-src https://accounts.google.com" in response.headers["Content-Security-Policy"]
    assert "youtube.com" not in response.headers["Content-Security-Policy"]
    assert "https://cdn.jsdelivr.net" not in response.headers["Content-Security-Policy"]
    assert "'wasm-unsafe-eval'" in response.headers["Content-Security-Policy"]
    assert "worker-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Server" not in response.headers


def test_vendored_qr_wasm_has_correct_media_type(security_app):
    _, client, _ = security_app
    response = client.get("/static/vendor/zxing-wasm/3.1.6/reader/zxing_reader.wasm")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/wasm")


def test_missing_static_asset_is_not_immutable(security_app):
    _, client, _ = security_app
    response = client.get("/static/missing-qr-worker.js")
    assert response.status_code == 404
    assert response.headers["Cache-Control"] == "no-store"


def test_api_responses_are_no_store(security_app):
    _, client, _ = security_app

    response = client.get("/api/app-runtime")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_cors_allows_only_configured_origins(security_app):
    _, client, _ = security_app
    headers = {
        "Origin": "https://safescan-qr.onrender.com",
        "Access-Control-Request-Method": "POST",
    }

    allowed = client.options("/api/scan", headers=headers)
    denied = client.options(
        "/api/scan",
        headers={**headers, "Origin": "https://evil.com"},
    )
    state_change = client.post(
        "/api/analyze",
        headers={"Origin": "https://evil.com"},
        json={"url": "https://example.com"},
    )

    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "https://safescan-qr.onrender.com"
    assert denied.status_code in (400, 403)
    assert "Access-Control-Allow-Origin" not in denied.headers
    assert state_change.status_code == 403


def test_session_cookie_uses_host_prefix(security_app):
    module, client, _ = security_app

    response = register(client, "cookie@example.com")

    assert response.status_code in (200, 303)
    assert module.SESSION_COOKIE_NAME == "__Host-safescan_session"
    assert "__Host-safescan_session" in client.cookies
    set_cookie = response.headers.get("set-cookie", "")
    assert "__Host-safescan_session=" in set_cookie
    assert "Secure" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie


def test_scan_history_rls_isolates_regular_users(security_app):
    _, client, db_path = security_app
    register(client, "user-a@example.com")
    add_scan(db_path, "user-a@example.com", "https://a.example")
    add_scan(db_path, "user-b@example.com", "https://b.example")

    response = client.get("/api/scan-history")

    assert response.status_code == 200
    urls = [row["url"] for row in response.json()]
    assert urls == ["https://a.example"]


def test_scan_history_rls_allows_admin_to_see_all_rows(security_app):
    _, client, db_path = security_app
    register(client, "admin@example.com")
    add_scan(db_path, "user-a@example.com", "https://a.example")
    add_scan(db_path, "user-b@example.com", "https://b.example")

    response = client.get("/api/scan-history")

    assert response.status_code == 200
    urls = {row["url"] for row in response.json()}
    assert urls == {"https://a.example", "https://b.example"}


def test_unauthenticated_scan_history_returns_401(security_app):
    _, client, _ = security_app

    response = client.get("/api/scan-history")

    assert response.status_code == 401


def test_waitlist_admin_page_requires_admin(security_app):
    _, client, db_path = security_app
    register(client, "user@example.com")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO waitlist_signups VALUES (?, ?, ?)",
            ("lead@example.com", "footer", "2026-05-11T12:00:00Z"),
        )

    response = client.get("/admin/waitlist", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_admin_can_view_waitlist_signups(security_app):
    _, client, db_path = security_app
    register(client, "admin@example.com")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO waitlist_signups VALUES (?, ?, ?)",
            ("lead@example.com", "footer", "2026-05-11T12:00:00Z"),
        )

    response = client.get("/admin/waitlist")

    assert response.status_code == 200
    assert "lead@example.com" in response.text
    assert "Waitlist" in response.text


def test_admin_user_detail_uses_stable_account_id_and_rejects_ambiguous_email(security_app):
    _, client, db_path = security_app
    register(client, "admin@example.com")
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO users (google_id, email, display_name) VALUES (?, ?, ?)",
            [("account-A", "shared@example.test", "Account A"),
             ("auth0|account/B", "SHARED@example.test", "Account B")],
        )
        conn.execute(
            "INSERT INTO scan_history (id, email, user_id, url, risk_score, verdict, signals, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("B-scan", "shared@example.test", "auth0|account/B", "https://b.example.test", 42,
             "CAUTION", "[]", "2026-11-04"),
        )

    a = client.get("/admin/users/detail", params={"account_id": "account-A"})
    b = client.get("/admin/users/detail", params={"account_id": "auth0|account/B"})
    ambiguous = client.get("/admin/users/shared@example.test/drawer")
    assert a.status_code == 200
    assert "Account A" in a.text
    assert "https://b.example.test" not in a.text
    assert b.status_code == 200
    assert "Account B" in b.text
    assert "https://b.example.test" not in b.text
    assert "Scan history is unavailable while account ownership is reviewed" in b.text
    assert ambiguous.status_code == 404


def test_admin_email_actions_fail_closed_for_duplicate_accounts(security_app):
    _, client, db_path = security_app
    register(client, "owner@example.com")
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO users (google_id, email) VALUES (?, ?)",
            [("account-A", "shared@example.test"), ("account-B", "SHARED@example.test")],
        )
        conn.execute(
            "INSERT INTO fraud_flags (id, user_id, check_name, severity, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("legacy-flag", "shared@example.test", "test", "medium", "Review", "2026-11-04"),
        )
        audit_before = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]

    for path, payload in (
        ("/admin/users/shared@example.test/suspend", {"action": "suspend"}),
        ("/admin/users/shared@example.test/role", {"role": "admin"}),
        ("/admin/users/shared@example.test/delete", {"confirm": "DELETE"}),
        ("/admin/airdrop/shared@example.test/status", {"status": "disqualified"}),
        ("/admin/fraud/shared@example.test/review", {"outcome": "disqualified"}),
    ):
        response = client.post(path, data=payload)
        assert response.status_code == 409
        assert "This account needs ownership review" in response.text

    missing = client.post("/admin/users/missing@example.test/suspend", data={"action": "suspend"})
    assert missing.status_code == 404
    assert "find that account" in missing.text
    assert "All Users" in missing.text

    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT google_id, status, role, airdrop_status FROM users "
            "WHERE google_id IN ('account-A', 'account-B') ORDER BY google_id"
        ).fetchall() == [
            ("account-A", "active", "user", "eligible"),
            ("account-B", "active", "user", "eligible"),
        ]
        assert conn.execute("SELECT reviewed FROM fraud_flags WHERE id = 'legacy-flag'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == audit_before


def test_fraud_review_includes_id_flags_without_assigning_shared_email_flags(security_app):
    module, client, db_path = security_app
    register(client, "admin@example.com")
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO users (google_id, email) VALUES (?, ?)",
            [("account-A", "shared@example.test"), ("account-B", "SHARED@example.test"),
             ("account-C", "unique@example.test")],
        )
        conn.executemany(
            "INSERT INTO fraud_flags (id, user_id, check_name, severity, reason, created_at) "
            "VALUES (?, ?, 'test', 'medium', 'Review', '2026-11-04')",
            [("A-id", "account-A"), ("B-id", "account-B"),
             ("shared-legacy", "shared@example.test"),
             ("unique-legacy", "UNIQUE@EXAMPLE.TEST")],
        )

    data = module.fetch_fraud_data()
    by_id = {row["google_id"]: row for row in data["rows"] if row["google_id"]}
    assert by_id["account-A"]["signal_count"] == 1
    assert by_id["account-B"]["signal_count"] == 1
    assert by_id["account-C"]["signal_count"] == 1
    assert by_id["account-A"]["ambiguous_email"] == 1
    assert by_id["account-C"]["ambiguous_email"] == 0
    unassigned = [row for row in data["rows"] if row["google_id"] is None]
    assert len(unassigned) == 1
    assert unassigned[0]["email"] == "shared@example.test"
    assert unassigned[0]["signal_count"] == 1
    page = client.get("/admin/airdrop/fraud")
    assert page.status_code == 200
    assert "Account ownership needs review; action unavailable" in page.text
    assert "No fraud flags to review" not in page.text
    reviewed = client.post("/admin/fraud/unique@example.test/review", data={"outcome": "cleared"}, follow_redirects=False)
    assert reviewed.status_code == 303
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT reviewed FROM fraud_flags WHERE id = 'unique-legacy'").fetchone()[0] == 1
        assert conn.execute("SELECT reviewed FROM fraud_flags WHERE id = 'shared-legacy'").fetchone()[0] == 0


def test_admin_user_actions_keep_invalid_input_without_mutation(security_app):
    _, client, db_path = security_app
    register(client, "owner@example.com")

    role = client.post("/admin/users/owner@example.com/role", data={"role": "root"})
    assert role.status_code == 400
    assert "All Users" in role.text
    assert "Choose an available action" in role.text
    assert 'aria-invalid="true"' in role.text

    confirmation = client.post("/admin/users/owner@example.com/delete", data={"confirm": "NO"})
    assert confirmation.status_code == 400
    assert 'value="NO"' in confirmation.text
    assert "Type DELETE to confirm" in confirmation.text

    suspend = client.post("/admin/users/owner@example.com/suspend", data={"action": "unexpected"})
    assert suspend.status_code == 400
    assert "All Users" in suspend.text
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT role, status FROM users WHERE email = ?", ("owner@example.com",)).fetchone() == ("owner", "active")


def test_admin_api_key_form_validates_before_creating_secret(security_app):
    _, client, db_path = security_app
    register(client, "owner@example.com")

    missing = client.post("/admin/api-keys", data={"name": "", "expires_at": ""})
    assert missing.status_code == 400
    assert "Enter a name for the API key" in missing.text
    assert 'id="api-key-name"' in missing.text

    expiry = client.post("/admin/api-keys", data={"name": "Reports", "expires_at": "yesterday"})
    assert expiry.status_code == 400
    assert 'value="Reports"' in expiry.text
    assert 'value="yesterday"' in expiry.text
    assert "Enter a valid expiry date" in expiry.text

    scopes = client.post("/admin/api-keys", data={"name": "Reports", "scopes": "owner:everything"})
    assert scopes.status_code == 400
    assert "Choose an available API key scope" in scopes.text
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 0

    valid = client.post("/admin/api-keys", data={"name": "Reports", "scopes": "risk:analyze", "expires_at": "2027-12-01"})
    assert valid.status_code == 200
    assert "This key will not be shown again" in valid.text
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 1


def test_admin_action_failures_return_their_own_page(security_app):
    _, client, db_path = security_app
    register(client, "owner@example.com")
    add_scan(db_path, "owner@example.com", "WIFI:T:WPA;S:Guest;P:secret;;")

    scan = client.post("/admin/scans/scan_owner/flag")
    assert scan.status_code == 400
    assert "All Scans" in scan.text
    assert "Only scans of web links" in scan.text

    report = client.post("/admin/reports/unknown/action", data={"action": "wrong"})
    assert report.status_code == 400
    assert "Reported URLs" in report.text
    assert "Choose an available action" in report.text

    airdrop = client.post("/admin/airdrop/owner@example.com/status", data={"status": "wrong", "reason": "Review pending"})
    assert airdrop.status_code == 400
    assert "Tier Overview" in airdrop.text

    fraud = client.post("/admin/fraud/owner@example.com/review", data={"outcome": "wrong", "reason": "Review pending"})
    assert fraud.status_code == 400
    assert "Fraud Flags" in fraud.text


def test_breach_form_keeps_input_and_escapes_saved_report(security_app):
    _, client, db_path = security_app
    register(client, "owner@example.com")
    invalid = client.post("/admin/report-breach", data={
        "discovery_date": "bad date", "data_categories": "Account data",
        "users_affected": "unknown", "likely_consequences": "Possible spam",
        "measures_taken": "Investigating",
    })
    assert invalid.status_code == 400
    assert 'value="bad date"' in invalid.text
    assert "Enter the discovery date" in invalid.text
    assert "Account data" in invalid.text
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM breach_reports").fetchone()[0] == 0

    report = client.post("/admin/report-breach", data={
        "discovery_date": "2026-11-15T10:00:00Z",
        "data_categories": "<script>alert(1)</script>",
        "users_affected": "unknown", "likely_consequences": "Possible spam",
        "measures_taken": "Investigating",
    })
    assert report.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report.text
    assert "<script>alert(1)</script>" not in report.text
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM breach_reports").fetchone()[0] == 1


def test_go_ghost_page_prompts_before_workflow(security_app):
    _, client, _ = security_app

    response = client.get("/go-ghost")

    assert response.status_code == 200
    assert 'id="goGhostConsentTitle"' in response.text
    assert 'id="startGoGhostButton"' in response.text
    assert "id=\"goGhostWorkspace\" hidden" in response.text
    assert "Never provide SSN" in response.text
    assert "broker-card" not in response.text


def test_admin_breach_preview_escapes_submitted_html(security_app):
    _, client, db_path = security_app
    assert register(client, "admin@example.com").status_code == 303
    payload = "<svg onload=alert(1)>"

    response = client.post(
        "/admin/report-breach",
        data={
            "discovery_date": "2026-11-14",
            "data_categories": payload,
            "users_affected": "1",
            "likely_consequences": "None known",
            "measures_taken": "Investigating",
        },
    )

    assert response.status_code == 200
    assert "&lt;svg onload=alert(1)&gt;" in response.text
    assert payload not in response.text
    with sqlite3.connect(db_path) as conn:
        stored = conn.execute("SELECT data_categories FROM breach_reports").fetchone()[0]
    assert stored == payload


def test_waitlist_export_requires_owner(security_app):
    _, admin_client, db_path = security_app
    register(admin_client, "admin@example.com")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO waitlist_signups VALUES (?, ?, ?)",
            ("lead@example.com", "footer", "2026-05-11T12:00:00Z"),
        )

    denied = admin_client.get("/admin/export/waitlist", follow_redirects=False)

    owner_client = TestClient(sys.modules["hackabull"].qr_app, base_url="https://testserver")
    register(owner_client, "owner@example.com")
    allowed = owner_client.get("/admin/export/waitlist")

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.headers["content-type"].startswith("text/csv")
    assert "lead@example.com" in allowed.text


def test_admin_access_denylist_removes_contact_email_access(tmp_path, monkeypatch):
    db_path = tmp_path / "denylist.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("ADMIN_EMAIL", "safescanqr@gmail.com")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@example.com,safescanqr@gmail.com")
    monkeypatch.setenv("OWNER_EMAILS", "owner@example.com,safescanqr@gmail.com")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")

    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
    module = importlib.import_module("hackabull")

    assert module.role_for_email("safescanqr@gmail.com") == "user"
    assert module.role_for_email("admin@example.com") == "admin"
    assert module.role_for_email("owner@example.com") == "owner"

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (google_id, email, display_name, role) VALUES (?, ?, ?, ?)",
            ("google_safescan", "safescanqr@gmail.com", "SafeScan Contact", "owner"),
        )

    module.init_db()

    with sqlite3.connect(db_path) as conn:
        role = conn.execute("SELECT role FROM users WHERE lower(email) = ?", ("safescanqr@gmail.com",)).fetchone()[0]

    assert role == "user"

    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
