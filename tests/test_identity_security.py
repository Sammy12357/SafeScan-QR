"""Federated identities must never inherit another account's privileges by email."""

import importlib
import csv
import io
import re
import sqlite3
import sys
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def identity_app(tmp_path, monkeypatch):
    database = tmp_path / "identity.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("OWNER_EMAILS", "owner@example.com")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@example.com")
    monkeypatch.delenv("RENDER", raising=False)
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(routes, "run_fraud_checks", lambda *args, **kwargs: [])
    app.RATE_LIMITS.clear()
    yield app, routes, database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def _rows(database, sql, params=()):
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, params)]


def _browser_form_post(client, path, data=None, *, include_origin=True):
    page = client.get("/")
    match = re.search(r'<meta name="csrf-token" content="([a-f0-9]{64})"', page.text)
    assert match
    headers = {"Origin": "https://testserver"} if include_origin else {}
    return client.post(
        path, data={**(data or {}), "csrf_token": match.group(1)},
        headers=headers, follow_redirects=False,
    )


def _auth0_client(app, routes, monkeypatch, *, subject, email, verified):
    monkeypatch.setattr(routes, "_decode_jwt_unverified", lambda token: ({}, {"iss": routes.AUTH0_ISSUER}, []))
    monkeypatch.setattr(
        routes,
        "verify_auth0_id_token",
        lambda token: {"sub": subject, "email": email, "email_verified": verified},
    )
    return TestClient(app.qr_app, base_url="https://testserver")


def _staff_client(app, database, email, role):
    client = TestClient(app.qr_app, base_url="https://testserver")
    app.RATE_LIMITS.clear()
    assert _browser_form_post(client, "/auth/register", {
        "email": email, "password": "password123",
    }).status_code == 303
    with sqlite3.connect(database) as conn:
        user_id = conn.execute("SELECT google_id FROM users WHERE email = ?", (email,)).fetchone()[0]
        conn.execute("UPDATE users SET role = ? WHERE google_id = ?", (role, user_id))
    return client, user_id


def test_google_unverified_email_cannot_sign_in(identity_app, monkeypatch):
    app, routes, database = identity_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    assert client.get("/login").status_code == 200
    client.cookies.set("g_csrf_token", "test-gis-csrf")
    monkeypatch.setattr(
        routes.id_token,
        "verify_oauth2_token",
        lambda *args: {"sub": "google-attacker", "email": "owner@example.com", "email_verified": False},
    )
    response = client.post(
        "/auth/google", data={"credential": "valid-token", "g_csrf_token": "test-gis-csrf"}
    )
    assert response.status_code == 401
    assert _rows(database, "SELECT * FROM users") == []
    assert _rows(database, "SELECT * FROM sessions") == []


def test_auth0_unverified_email_cannot_sign_in(identity_app, monkeypatch):
    app, routes, database = identity_app
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="github|attacker", email="owner@example.com", verified="false",
    )
    response = client.post("/auth/verify", json={"token": "valid-token"})
    assert response.status_code == 401
    assert _rows(database, "SELECT * FROM users") == []
    assert _rows(database, "SELECT * FROM sessions") == []


def test_different_verified_subject_cannot_silently_claim_existing_email(identity_app, monkeypatch):
    app, routes, database = identity_app
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO users (google_id, email, role, google_sub) VALUES (?, ?, ?, ?)",
            ("trusted-google-sub", "owner@example.com", "owner", "trusted-google-sub"),
        )
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="github|different-sub", email="owner@example.com", verified=True,
    )
    response = client.post("/auth/verify", json={"token": "valid-token"})
    assert response.status_code in {401, 409}
    assert _rows(database, "SELECT google_id, role FROM users") == [
        {"google_id": "trusted-google-sub", "role": "owner"}
    ]
    assert _rows(database, "SELECT * FROM sessions") == []


def test_auth0_connection_prefix_remains_part_of_subject(identity_app, monkeypatch):
    app, routes, database = identity_app
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="google-oauth2|same-suffix", email="one@example.com", verified=True,
    )
    first = client.post("/auth/verify", json={"token": "valid-token"})
    assert first.status_code == 200
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="github|same-suffix", email="two@example.com", verified=True,
    )
    second = client.post("/auth/verify", json={"token": "valid-token"})
    assert second.status_code == 200
    assert second.json()["user"]["id"] != first.json()["user"]["id"]
    assert len(_rows(database, "SELECT google_id FROM users")) == 2


def test_returning_identity_keeps_same_account_and_role(identity_app, monkeypatch):
    app, routes, database = identity_app
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="google-oauth2|returning", email="returning@example.com", verified="true",
    )
    first = client.post("/auth/verify", json={"token": "valid-token"})
    assert first.status_code == 200
    user_id = first.json()["user"]["id"]
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'admin' WHERE google_id = ?", (user_id,))

    second = client.post("/auth/verify", json={"token": "valid-token"})

    assert second.status_code == 200
    assert second.json()["user"]["id"] == user_id
    assert second.json()["user"]["role"] == "admin"
    assert _rows(database, "SELECT issuer, subject, user_id FROM user_identities") == [{
        "issuer": routes.AUTH0_ISSUER,
        "subject": "google-oauth2|returning",
        "user_id": user_id,
    }]


def test_verified_identity_with_changed_email_requires_review(identity_app, monkeypatch):
    app, routes, database = identity_app
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="google-oauth2|stable", email="first@example.com", verified=True,
    )
    first = client.post("/auth/verify", json={"token": "valid-token"})
    assert first.status_code == 200
    sessions_before = len(_rows(database, "SELECT id FROM sessions"))
    client = _auth0_client(
        app, routes, monkeypatch,
        subject="google-oauth2|stable", email="second@example.com", verified=True,
    )
    changed = client.post("/auth/verify", json={"token": "valid-token"})
    assert changed.status_code == 409
    assert len(_rows(database, "SELECT id FROM sessions")) == sessions_before
    assert _rows(database, "SELECT email FROM users") == [{"email": "first@example.com"}]


def test_local_registration_never_grants_owner_role_from_email(identity_app):
    app, routes, database = identity_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    response = _browser_form_post(client, "/auth/register",
                                  {"email": "owner@example.com", "password": "password123"})
    assert response.status_code == 303
    assert _rows(database, "SELECT role FROM users") == [{"role": "user"}]
    app.init_db()
    assert _rows(database, "SELECT role FROM users") == [{"role": "user"}]


def test_role_change_refuses_ambiguous_email(identity_app):
    app, routes, database = identity_app
    owner = TestClient(app.qr_app, base_url="https://testserver")
    registered = _browser_form_post(owner, "/auth/register",
                                    {"email": "operator@example.com", "password": "password123"})
    assert registered.status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'operator@example.com'")
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("account-a", "shared@example.com"))
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("account-b", "shared@example.com"))

    response = _browser_form_post(owner, "/admin/users/shared@example.com/role", {"role": "admin"})

    assert response.status_code == 409
    assert _rows(database, "SELECT role FROM users WHERE email = 'shared@example.com'") == [
        {"role": "user"}, {"role": "user"}
    ]


@pytest.mark.parametrize("path, helper", [
    ("/admin", "dashboard_data"),
    ("/admin/activity", "fetch_audit_logs"),
    ("/admin/users", "fetch_admin_users"),
    ("/admin/scans", "fetch_scans"),
    ("/admin/waitlist", "fetch_waitlist"),
    ("/admin/reports", "fetch_reports"),
    ("/admin/risk-logs", "fetch_scans"),
    ("/admin/airdrop", "fetch_airdrop_data"),
    ("/admin/airdrop/fraud", "fetch_fraud_data"),
    ("/admin/airdrop/wallets", "fetch_airdrop_data"),
    ("/admin/logs", "fetch_audit_logs"),
])
def test_admin_read_authorizes_before_fetch(identity_app, monkeypatch, path, helper):
    app, _, database = identity_app
    routes_admin = importlib.import_module("hackabull.routes_admin")
    client, _ = _staff_client(app, database, "reader@example.com", "user")

    def forbidden_fetch(*args, **kwargs):
        raise AssertionError("Admin data was read before authorization")

    monkeypatch.setattr(routes_admin, helper, forbidden_fetch)
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


@pytest.mark.parametrize("path", ["/admin/api-keys", "/admin/settings"])
def test_owner_page_authorizes_before_database_read(identity_app, monkeypatch, path):
    app, _, database = identity_app
    routes_admin = importlib.import_module("hackabull.routes_admin")
    admin, _ = _staff_client(app, database, "admin@example.com", "admin")

    def forbidden_connection(*args, **kwargs):
        raise AssertionError("Owner data was read before authorization")

    monkeypatch.setattr(routes_admin, "get_conn", forbidden_connection)
    response = admin.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_audit_export_authorizes_owner_before_fetch(identity_app, monkeypatch):
    app, _, database = identity_app
    routes_admin = importlib.import_module("hackabull.routes_admin")
    admin, _ = _staff_client(app, database, "admin@example.com", "admin")

    def forbidden_fetch(*args, **kwargs):
        raise AssertionError("Audit rows were read before owner authorization")

    monkeypatch.setattr(routes_admin, "fetch_audit_logs", forbidden_fetch)
    assert admin.get("/admin/logs?export=csv").status_code == 403


def test_admin_actions_respect_role_hierarchy_and_exact_account(identity_app):
    app, _, database = identity_app
    owner, owner_id = _staff_client(app, database, "owner1@example.com", "owner")
    admin, admin_id = _staff_client(app, database, "admin1@example.com", "admin")
    _, second_admin_id = _staff_client(app, database, "admin2@example.com", "admin")
    _, user_id = _staff_client(app, database, "user@example.com", "user")

    users_page = owner.get("/admin/users")
    assert users_page.status_code == 200
    assert f"/admin/users/{user_id}/suspend" in users_page.text
    assert f"/admin/users/{owner_id}/suspend" not in users_page.text
    assert f"/admin/users/{owner_id}/delete" not in users_page.text

    assert _browser_form_post(admin, f"/admin/users/{quote(owner_id, safe='')}/suspend").status_code == 403
    assert _browser_form_post(admin, f"/admin/users/{quote(second_admin_id, safe='')}/suspend").status_code == 403
    assert _browser_form_post(admin, f"/admin/users/{quote(user_id, safe='')}/role", {"role": "owner"}).status_code == 403
    assert _browser_form_post(admin, f"/admin/users/{quote(user_id, safe='')}/delete", {"confirm": "DELETE"}).status_code == 403
    assert _browser_form_post(owner, f"/admin/users/{quote(owner_id, safe='')}/suspend").status_code == 403
    assert _browser_form_post(owner, f"/admin/users/{quote(owner_id, safe='')}/delete", {"confirm": "DELETE"}).status_code == 403
    assert _browser_form_post(admin, f"/admin/users/{quote(user_id, safe='')}/suspend").status_code == 303
    assert _browser_form_post(owner, f"/admin/users/{quote(admin_id, safe='')}/suspend").status_code == 303
    assert _rows(database, "SELECT google_id, status FROM users WHERE google_id IN (?, ?, ?, ?) ORDER BY google_id", (owner_id, admin_id, second_admin_id, user_id)) == sorted([
        {"google_id": owner_id, "status": "active"},
        {"google_id": admin_id, "status": "suspended"},
        {"google_id": second_admin_id, "status": "active"},
        {"google_id": user_id, "status": "suspended"},
    ], key=lambda row: row["google_id"])
    assert _browser_form_post(owner, f"/admin/users/{quote(user_id, safe='')}/delete", {"confirm": "DELETE"}).status_code == 303
    assert _rows(database, "SELECT status FROM users WHERE google_id = ?", (user_id,)) == [{"status": "deleted"}]


def test_last_owner_cannot_be_demoted_and_owner_cannot_demote_peer(identity_app):
    app, _, database = identity_app
    owner, owner_id = _staff_client(app, database, "owner1@example.com", "owner")
    _, user_id = _staff_client(app, database, "user@example.com", "user")

    assert _browser_form_post(owner, f"/admin/users/{quote(owner_id, safe='')}/role", {"role": "admin"}).status_code == 409
    assert _rows(database, "SELECT role FROM users WHERE google_id = ?", (owner_id,)) == [{"role": "owner"}]

    assert _browser_form_post(owner, f"/admin/users/{quote(user_id, safe='')}/role", {"role": "owner"}).status_code == 303
    assert _browser_form_post(owner, f"/admin/users/{quote(user_id, safe='')}/role", {"role": "user"}).status_code == 403
    assert _browser_form_post(owner, f"/admin/users/{quote(user_id, safe='')}/suspend").status_code == 403
    assert _browser_form_post(owner, f"/admin/users/{quote(user_id, safe='')}/delete", {"confirm": "DELETE"}).status_code == 403
    assert _browser_form_post(owner, f"/admin/users/{quote(owner_id, safe='')}/role", {"role": "admin"}).status_code == 303
    assert _rows(database, "SELECT role, status FROM users WHERE role = 'owner' AND status = 'active'") == [{"role": "owner", "status": "active"}]


def test_suspend_and_delete_refuse_ambiguous_email(identity_app):
    app, _, database = identity_app
    owner, _ = _staff_client(app, database, "owner1@example.com", "owner")
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("account-a", "shared@example.com"))
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("account-b", "shared@example.com"))

    assert _browser_form_post(owner, "/admin/users/shared@example.com/suspend").status_code == 409
    assert _browser_form_post(owner, "/admin/users/shared@example.com/delete", {"confirm": "DELETE"}).status_code == 409
    assert _rows(database, "SELECT google_id, status FROM users WHERE email = ? ORDER BY google_id", ("shared@example.com",)) == [
        {"google_id": "account-a", "status": "active"},
        {"google_id": "account-b", "status": "active"},
    ]


def test_self_service_erasure_preserves_last_owner(identity_app):
    app, _, database = identity_app
    owner, owner_id = _staff_client(app, database, "owner1@example.com", "owner")

    response = _browser_form_post(owner, "/legal/data-request", {
        "email": "OWNER1@EXAMPLE.COM", "request_type": "erasure",
    })

    assert response.status_code == 200
    assert _rows(database, "SELECT google_id FROM users WHERE google_id = ?", (owner_id,)) == [{"google_id": owner_id}]
    assert _rows(database, "SELECT status FROM data_requests WHERE request_type = 'erasure'") == [{"status": "submitted"}]


def test_self_service_erasure_requires_unique_exact_identity(identity_app):
    app, _, database = identity_app
    owner, owner_id = _staff_client(app, database, "owner1@example.com", "owner")
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("collision", "OWNER1@example.com"))

    response = _browser_form_post(owner, "/legal/data-request", {
        "email": "owner1@example.com", "request_type": "erasure",
    })

    assert response.status_code == 200
    assert _rows(database, "SELECT google_id FROM users WHERE lower(email) = ? ORDER BY google_id", ("owner1@example.com",)) == [
        {"google_id": "collision"}, {"google_id": owner_id},
    ]
    assert _rows(database, "SELECT status FROM data_requests WHERE request_type = 'erasure'") == [{"status": "submitted"}]


def test_erasure_helper_rejects_mismatched_account_id(identity_app):
    app, _, database = identity_app
    _, first_id = _staff_client(app, database, "first@example.com", "user")
    _, second_id = _staff_client(app, database, "second@example.com", "user")
    legal = importlib.import_module("hackabull.legal")

    assert legal.delete_user_data("first@example.com", second_id) is False
    assert _rows(database, "SELECT google_id FROM users ORDER BY email") == [
        {"google_id": first_id}, {"google_id": second_id},
    ]


def test_self_service_erasure_can_remove_owner_after_transfer(identity_app):
    app, _, database = identity_app
    owner, owner_id = _staff_client(app, database, "owner1@example.com", "owner")
    _, second_owner_id = _staff_client(app, database, "owner2@example.com", "owner")

    response = _browser_form_post(owner, "/legal/data-request", {
        "email": "owner1@example.com", "request_type": "erasure",
    })

    assert response.status_code == 200
    assert _rows(database, "SELECT google_id FROM users WHERE role = 'owner'") == [{"google_id": second_owner_id}]
    assert _rows(database, "SELECT status FROM data_requests WHERE request_type = 'erasure'") == [{"status": "completed"}]


@pytest.mark.parametrize("path, helper, field", [
    ("/admin/export/users", "fetch_admin_users", "email"),
    ("/admin/export/waitlist", "fetch_waitlist", "source"),
    ("/admin/logs?export=csv", "fetch_audit_logs", "metadata"),
])
def test_admin_csv_exports_escape_formula_cells(identity_app, monkeypatch, path, helper, field):
    app, _, database = identity_app
    routes_admin = importlib.import_module("hackabull.routes_admin")
    owner, _ = _staff_client(app, database, "owner1@example.com", "owner")
    payload = " \t=HYPERLINK(\"https://attacker.example\")"
    monkeypatch.setattr(routes_admin, helper, lambda *args, **kwargs: {"rows": [{field: payload}]})

    response = owner.get(path)
    assert response.status_code == 200
    assert next(csv.DictReader(io.StringIO(response.text)))[field] == "'" + payload


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-1+2", "@SUM(A1)", "\t=1", "\r=1", "\n=1", "   =1"])
def test_admin_csv_cell_sanitizer_handles_spreadsheet_prefixes(identity_app, value):
    routes_admin = importlib.import_module("hackabull.routes_admin")
    assert routes_admin._safe_csv_cell(value) == "'" + value
    assert routes_admin._safe_csv_cell("ordinary@example.com") == "ordinary@example.com"


def test_airdrop_secret_never_appears_in_state_changing_get(identity_app, monkeypatch):
    app, routes, _ = identity_app
    account_routes = importlib.import_module("hackabull.routes_account")
    monkeypatch.setattr(account_routes, "AIRDROP_ADMIN_SECRET", "s" * 32)
    async def fake_sweep():
        raise AssertionError("The test must not run an airdrop sweep")
    monkeypatch.setattr(importlib.import_module("distribute"), "airdrop_sweep", fake_sweep)
    client = TestClient(app.qr_app, base_url="https://testserver")

    assert client.get("/trigger-airdrop-secret", params={"secret": "s" * 32}).status_code == 405
    assert client.post("/trigger-airdrop-secret", params={"secret": "s" * 32}).status_code == 403


def test_airdrop_admin_post_requires_same_origin(identity_app):
    app, routes, database = identity_app
    owner = TestClient(app.qr_app, base_url="https://testserver")
    assert _browser_form_post(owner, "/auth/register",
                              {"email": "operator@example.com", "password": "password123"}).status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'operator@example.com'")

    assert _browser_form_post(owner, "/trigger-airdrop-secret", include_origin=False).status_code == 403


def test_admin_airdrop_distribute_rejects_missing_origin(identity_app, monkeypatch):
    app, routes, database = identity_app
    owner = TestClient(app.qr_app, base_url="https://testserver")
    assert _browser_form_post(owner, "/auth/register",
                              {"email": "operator@example.com", "password": "password123"}).status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'operator@example.com'")

    calls = []
    async def fake_sweep():
        calls.append(True)
        return {"status": "dry_run", "eligible": 0, "sent": [], "total_tokens_sent": 0}
    monkeypatch.setattr(importlib.import_module("distribute"), "airdrop_sweep", fake_sweep)
    assert _browser_form_post(owner, "/admin/airdrop/distribute", include_origin=False).status_code == 403
    assert calls == []
    assert _browser_form_post(owner, "/admin/airdrop/distribute").status_code == 200
    assert calls == [True]


def test_airdrop_header_secret_allows_one_post_without_browser_cookie(identity_app, monkeypatch):
    app, routes, _ = identity_app
    account_routes = importlib.import_module("hackabull.routes_account")
    monkeypatch.setattr(account_routes, "AIRDROP_ADMIN_SECRET", "s" * 32)
    calls = []
    async def fake_sweep():
        calls.append(True)
        return {"status": "dry_run", "eligible": 0, "sent": [], "total_tokens_sent": 0}
    monkeypatch.setattr(importlib.import_module("distribute"), "airdrop_sweep", fake_sweep)
    client = TestClient(app.qr_app, base_url="https://testserver")

    assert client.post("/trigger-airdrop-secret", headers={"X-Airdrop-Secret": "wrong"}).status_code == 403
    allowed = client.post("/trigger-airdrop-secret", headers={"X-Airdrop-Secret": "s" * 32})

    assert allowed.status_code == 200
    assert calls == [True]
