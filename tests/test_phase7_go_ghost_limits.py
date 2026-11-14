"""Go Ghost launches at most one bounded browser job per worker and account."""

import asyncio
import importlib
import json
import sqlite3
import sys
from types import ModuleType

import httpx
import pytest

from browser_client import BrowserTestClient


PROFILE = {"name": "Person", "email": "person@example.com"}


@pytest.fixture()
def ghost_app(tmp_path, monkeypatch):
    db_path = tmp_path / "ghost.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    pages = importlib.import_module("hackabull.routes_pages")
    import removals.engine as engine

    app.RATE_LIMITS.clear()
    monkeypatch.setattr(pages, "require_user", lambda request: {"google_id": "person", "email": "person@example.com"})
    monkeypatch.setattr(engine, "supported_broker", lambda _broker: type("Broker", (), {"optout_url": "https://example.com", "name": "Example"})())
    yield app.qr_app, pages, engine, db_path, monkeypatch
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _jobs(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            "SELECT user_id, status, detail FROM go_ghost_removal_jobs ORDER BY created_at"
        ).fetchall()]


def test_second_request_does_not_launch_or_consume_quota_while_browser_busy(ghost_app):
    app, _pages, engine, db_path, monkeypatch = ghost_app
    started = asyncio.Event()
    release = asyncio.Event()
    runs = []

    async def slow_run(*_args):
        runs.append("started")
        started.set()
        await release.wait()
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", slow_run)

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            first_task = asyncio.create_task(client.post("/api/go-ghost/removals/example", json=PROFILE))
            await asyncio.wait_for(started.wait(), timeout=2)
            second = await client.post("/api/go-ghost/removals/example", json=PROFILE)
            release.set()
            first = await first_task
            return first, second

    first, second = asyncio.run(exercise())
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == "5"
    assert runs == ["started"]
    assert [job["status"] for job in _jobs(db_path)] == ["submitted"]

    async def done(*_args):
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    client = BrowserTestClient(app, base_url="https://testserver")
    assert client.post("/api/go-ghost/removals/example", json=PROFILE).status_code == 200
    assert client.post("/api/go-ghost/removals/example", json=PROFILE).status_code == 200
    assert client.post("/api/go-ghost/removals/example", json=PROFILE).status_code == 429
    assert len(_jobs(db_path)) == 3


def test_timeout_records_failure_and_releases_browser_slot(ghost_app):
    app, pages, engine, db_path, monkeypatch = ghost_app
    monkeypatch.setattr(pages, "GO_GHOST_RUN_TIMEOUT_SECONDS", 0.01)

    async def hung_run(*_args):
        await asyncio.Event().wait()

    monkeypatch.setattr(engine, "run_broker_removal", hung_run)
    client = BrowserTestClient(app, base_url="https://testserver")
    timed_out = client.post("/api/go-ghost/removals/example", json=PROFILE)
    assert timed_out.status_code == 200
    assert timed_out.json()["status"] == "failed"
    assert "timed out" in timed_out.json()["detail"]
    assert _jobs(db_path)[0]["status"] == "failed"

    async def done(*_args):
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    retried = client.post("/api/go-ghost/removals/example", json=PROFILE)
    assert retried.status_code == 200
    assert [job["status"] for job in _jobs(db_path)] == ["failed", "submitted"]


def test_stale_job_is_marked_interrupted_before_new_reservation(ghost_app):
    app, _pages, engine, db_path, monkeypatch = ghost_app
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO go_ghost_removal_jobs
               (id, user_id, email, broker, status, detail, target_url, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old", "person", "person@example.com", "example", "running", "started", "https://example.com", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z"),
        )

    async def done(*_args):
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    client = BrowserTestClient(app, base_url="https://testserver")
    response = client.post("/api/go-ghost/removals/example", json=PROFILE)
    assert response.status_code == 200
    assert [job["status"] for job in _jobs(db_path)] == ["interrupted", "submitted"]


def test_live_database_reservation_blocks_duplicate_same_account(ghost_app):
    _app, pages, _engine, db_path, _monkeypatch = ghost_app
    first = pages._reserve_go_ghost_job("person", "person@example.com", "example", "https://example.com", "one")
    second = pages._reserve_go_ghost_job("person", "person@example.com", "example", "https://example.com", "two")
    assert first is True
    assert second is False
    assert [job["status"] for job in _jobs(db_path)] == ["running"]


def test_live_job_from_another_worker_blocks_same_account_before_launch(ghost_app):
    app, pages, engine, db_path, monkeypatch = ghost_app
    now = pages.now_iso()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO go_ghost_removal_jobs
               (id, user_id, email, broker, status, detail, target_url, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("other-worker", "person", "person@example.com", "example", "running", "started", "https://example.com", now, now),
        )

    async def should_not_launch(*_args):
        pytest.fail("a live job on another worker must block this launch")

    monkeypatch.setattr(engine, "run_broker_removal", should_not_launch)
    client = BrowserTestClient(app, base_url="https://testserver")
    response = client.post("/api/go-ghost/removals/example", json=PROFILE)
    assert response.status_code == 429
    assert len(_jobs(db_path)) == 1


@pytest.mark.parametrize("attestation,expected_status", [
    (None, 403),
    (False, 403),
    ("true", 400),
])
def test_other_person_request_requires_explicit_boolean_attestation(ghost_app, attestation, expected_status):
    app, _pages, engine, db_path, monkeypatch = ghost_app

    async def should_not_launch(*_args):
        pytest.fail("automation must not run without valid authorization attestation")

    monkeypatch.setattr(engine, "run_broker_removal", should_not_launch)
    profile = {"name": "Relative", "email": "relative@example.com"}
    if attestation is not None:
        profile["delegateAttestation"] = attestation

    response = BrowserTestClient(app, base_url="https://testserver").post(
        "/api/go-ghost/removals/example", json=profile,
    )
    assert response.status_code == expected_status
    assert _jobs(db_path) == []
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'go_ghost.delegated_attestation'"
        ).fetchone()[0] == 0


def test_delegated_request_records_minimal_attestation_with_job(ghost_app):
    app, _pages, engine, db_path, monkeypatch = ghost_app

    async def done(*_args):
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    response = BrowserTestClient(app, base_url="https://testserver").post(
        "/api/go-ghost/removals/example",
        json={"name": "Relative", "email": "relative@example.com", "delegateAttestation": True},
    )
    assert response.status_code == 200
    assert _jobs(db_path)[0]["status"] == "submitted"
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """SELECT actor_user_id, target_type, target_id, metadata, ip_address, user_agent
               FROM audit_logs WHERE action = 'go_ghost.delegated_attestation'"""
        ).fetchone()
    assert row is not None
    assert row[:3] == ("person", "go_ghost_job", response.json()["jobId"])
    assert json.loads(row[3]) == {"broker": "example", "authorized": True}
    assert row[4:] == (None, None)
    assert "relative@example.com" not in repr(row)
    assert "Relative" not in repr(row)


def test_same_email_needs_no_delegation_attestation(ghost_app):
    app, _pages, engine, db_path, monkeypatch = ghost_app

    async def done(*_args):
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    client = BrowserTestClient(app, base_url="https://testserver")
    page = client.get("/go-ghost")
    assert page.status_code == 200
    assert 'id="ghostDelegateAttestationInput" type="checkbox"' in page.text
    assert 'data-account-email=""' in page.text  # This fixture has no browser session.
    response = client.post("/api/go-ghost/removals/example", json={"name": "Person", "email": "PERSON@example.com"})
    assert response.status_code == 200
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'go_ghost.delegated_attestation'"
        ).fetchone()[0] == 0


def test_browser_closes_when_page_creation_is_cancelled(monkeypatch):
    from removals.engine import RemovalProfile, run_broker_removal

    closed = []

    class Browser:
        async def new_page(self, **_kwargs):
            raise asyncio.CancelledError()

        async def close(self):
            closed.append(True)

    class Chromium:
        async def launch(self, **_kwargs):
            return Browser()

    class Playwright:
        chromium = Chromium()

    class Manager:
        async def __aenter__(self):
            return Playwright()

        async def __aexit__(self, *_args):
            return False

    api = ModuleType("playwright.async_api")
    api.TimeoutError = TimeoutError
    api.async_playwright = lambda: Manager()
    monkeypatch.setitem(sys.modules, "playwright", ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.async_api", api)

    async def run():
        with pytest.raises(asyncio.CancelledError):
            await run_broker_removal("fastpeoplesearch", RemovalProfile(name="Person", email="person@example.com"))

    asyncio.run(run())
    assert closed == [True]
