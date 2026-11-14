"""A request must never inherit another request's row-access role."""

import asyncio
import importlib
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from starlette.concurrency import run_in_threadpool


@pytest.fixture()
def app_with_users(tmp_path, monkeypatch):
    db_path = tmp_path / "rls-concurrency.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("AIRDROP_ENABLED", "false")

    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    module = importlib.import_module("hackabull")
    module.init_db()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with sqlite3.connect(db_path) as conn:
        for user_id, email, role in (
            ("google_admin", "admin@example.com", "admin"),
            ("google_user", "user@example.com", "user"),
        ):
            conn.execute(
                "INSERT INTO users (google_id, email, role, status, created_at) VALUES (?, ?, ?, 'active', ?)",
                (user_id, email, role, now.isoformat() + "Z"),
            )
        for session_id, user_id in (
            ("admin-test-session", "google_admin"),
            ("user-test-session", "google_user"),
        ):
            conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id, user_id, now.isoformat() + "Z",
                    (now + timedelta(hours=1)).isoformat() + "Z",
                    now.isoformat() + "Z", None, None, "test",
                ),
            )
        for email, url in (
            ("admin@example.com", "https://admin.example"),
            ("user@example.com", "https://user.example"),
        ):
            conn.execute(
                """INSERT INTO scan_history
                   (id, email, url, risk_score, verdict, signals, reported, created_at)
                   VALUES (?, ?, ?, 0, 'SAFE', '[]', 0, ?)""",
                (f"scan-{email}", email, url, now.isoformat() + "Z"),
            )

    yield module

    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)


def test_concurrent_admin_request_cannot_expand_user_history(app_with_users):
    async def exercise():
        transport = httpx.ASGITransport(app=app_with_users.qr_app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            user_headers = {"Authorization": "Bearer user-test-session"}
            admin_headers = {"Authorization": "Bearer admin-test-session"}
            sequential = await client.get("/api/history", headers=user_headers)
            assert sequential.status_code == 200
            assert {row["url"] for row in sequential.json()} == {"https://user.example"}

            requests = []
            for _ in range(30):
                requests.append(client.get("/api/history", headers=user_headers))
                requests.append(client.get("/api/history", headers=admin_headers))
            responses = await asyncio.gather(*requests)

        for response in responses[::2]:
            assert response.status_code == 200
            assert {row["url"] for row in response.json()} == {"https://user.example"}
        for response in responses[1::2]:
            assert response.status_code == 200
            assert {row["url"] for row in response.json()} == {
                "https://admin.example", "https://user.example",
            }

    asyncio.run(exercise())


def test_rls_context_is_copied_to_sync_worker(app_with_users):
    db = importlib.import_module("db")
    db.set_rls_context("google_user", role="user", email="user@example.com")
    try:
        async def read_in_worker():
            return await run_in_threadpool(
                lambda: (db.rls_user_id(), db.rls_role(), db.rls_email())
            )

        assert asyncio.run(read_in_worker()) == (
            "google_user", "user", "user@example.com",
        )
    finally:
        db.clear_rls_context()
