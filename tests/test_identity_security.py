"""Federated identities must never inherit another account's privileges by email."""

import importlib
import sqlite3
import sys

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


def _auth0_client(app, routes, monkeypatch, *, subject, email, verified):
    monkeypatch.setattr(routes, "_decode_jwt_unverified", lambda token: ({}, {"iss": routes.AUTH0_ISSUER}, []))
    monkeypatch.setattr(
        routes,
        "verify_auth0_id_token",
        lambda token: {"sub": subject, "email": email, "email_verified": verified},
    )
    return TestClient(app.qr_app, base_url="https://testserver")


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
    response = client.post(
        "/auth/register", data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert _rows(database, "SELECT role FROM users") == [{"role": "user"}]
    app.init_db()
    assert _rows(database, "SELECT role FROM users") == [{"role": "user"}]


def test_role_change_refuses_ambiguous_email(identity_app):
    app, routes, database = identity_app
    owner = TestClient(app.qr_app, base_url="https://testserver")
    registered = owner.post(
        "/auth/register", data={"email": "operator@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert registered.status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'operator@example.com'")
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("account-a", "shared@example.com"))
        conn.execute("INSERT INTO users (google_id, email) VALUES (?, ?)", ("account-b", "shared@example.com"))

    response = owner.post("/admin/users/shared@example.com/role", data={"role": "admin"}, follow_redirects=False)

    assert response.status_code == 409
    assert _rows(database, "SELECT role FROM users WHERE email = 'shared@example.com'") == [
        {"role": "user"}, {"role": "user"}
    ]


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
    assert owner.post(
        "/auth/register", data={"email": "operator@example.com", "password": "password123"},
        follow_redirects=False,
    ).status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'operator@example.com'")

    assert owner.post("/trigger-airdrop-secret").status_code == 403


def test_admin_airdrop_distribute_rejects_missing_origin(identity_app, monkeypatch):
    app, routes, database = identity_app
    owner = TestClient(app.qr_app, base_url="https://testserver")
    assert owner.post(
        "/auth/register", data={"email": "operator@example.com", "password": "password123"},
        follow_redirects=False,
    ).status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'operator@example.com'")

    calls = []
    async def fake_sweep():
        calls.append(True)
        return {"status": "dry_run", "eligible": 0, "sent": [], "total_tokens_sent": 0}
    monkeypatch.setattr(importlib.import_module("distribute"), "airdrop_sweep", fake_sweep)
    assert owner.post("/admin/airdrop/distribute").status_code == 403
    assert calls == []
    assert owner.post(
        "/admin/airdrop/distribute", headers={"Origin": "https://testserver"}
    ).status_code == 200
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
