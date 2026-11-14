"""Local password routes must stay unavailable outside development mode."""

import importlib
import sqlite3
import sys

import pytest
from browser_client import BrowserTestClient as TestClient


@pytest.fixture()
def local_auth_app(tmp_path, monkeypatch, request):
    db_path = tmp_path / "local-auth.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    if getattr(request, "param", False):
        monkeypatch.setenv("RENDER", "true")
    else:
        monkeypatch.delenv("RENDER", raising=False)
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    app.RATE_LIMITS.clear()
    monkeypatch.setattr(routes, "run_fraud_checks", lambda *args, **kwargs: [])
    yield app, routes, db_path
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def row_count(db_path, table):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_register_cannot_create_a_local_account_when_disabled(local_auth_app, monkeypatch):
    app, routes, db_path = local_auth_app
    monkeypatch.setattr(routes, "LOCAL_AUTH_ENABLED", False)
    client = TestClient(app.qr_app, base_url="https://testserver")

    response = client.post("/auth/register", data={"email": "owner@example.com", "password": "password123"})

    assert response.status_code == 404
    assert row_count(db_path, "users") == 0
    assert row_count(db_path, "local_credentials") == 0
    assert row_count(db_path, "sessions") == 0
    assert client.post("/auth/register", data={}).status_code == 404


def test_existing_local_credentials_cannot_log_in_when_disabled(local_auth_app, monkeypatch):
    app, routes, db_path = local_auth_app
    development = TestClient(app.qr_app, base_url="https://testserver")
    registered = development.post(
        "/auth/register", data={"email": "existing@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert registered.status_code == 303
    assert row_count(db_path, "local_credentials") == 1
    sessions_before = row_count(db_path, "sessions")

    monkeypatch.setattr(routes, "LOCAL_AUTH_ENABLED", False)
    public = TestClient(app.qr_app, base_url="https://testserver")
    blocked = public.post("/auth/login", data={"email": "existing@example.com", "password": "password123"})

    assert blocked.status_code == 404
    assert public.post("/auth/login", data={}).status_code == 404
    assert row_count(db_path, "sessions") == sessions_before


def test_local_registration_and_login_still_work_in_development(local_auth_app):
    app, routes, db_path = local_auth_app
    assert routes.LOCAL_AUTH_ENABLED is True
    client = TestClient(app.qr_app, base_url="https://testserver")
    registered = client.post(
        "/auth/register", data={"email": "developer@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert registered.status_code == 303
    assert row_count(db_path, "local_credentials") == 1

    new_client = TestClient(app.qr_app, base_url="https://testserver")
    logged_in = new_client.post(
        "/auth/login", data={"email": "developer@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert logged_in.status_code == 303
    assert app.SESSION_COOKIE_NAME in new_client.cookies


@pytest.mark.parametrize("local_auth_app", [True], indirect=True)
def test_render_disables_local_auth_even_if_mock_mode_is_set(local_auth_app):
    app, routes, db_path = local_auth_app
    assert routes.LOCAL_AUTH_ENABLED is False
    client = TestClient(app.qr_app, base_url="https://testserver")
    response = client.post("/auth/register", data={"email": "attacker@example.com", "password": "password123"})
    assert response.status_code == 404
    assert row_count(db_path, "users") == 0
