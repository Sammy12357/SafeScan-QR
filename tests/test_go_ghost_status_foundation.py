"""The inert Go Ghost server foundation must preserve account and claim scope."""

from __future__ import annotations

import importlib
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def foundation(tmp_path, monkeypatch):
    database = tmp_path / "go-ghost-status.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    # No environment switch may turn the unfinished API on.
    monkeypatch.setenv("GO_GHOST_STATUS_SYNC_ENABLED", "true")
    monkeypatch.delenv("RENDER", raising=False)
    for name in tuple(sys.modules):
        if name == "db" or name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    db = importlib.import_module("db")
    status = importlib.import_module("hackabull.go_ghost_status")
    with sqlite3.connect(database) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'go_ghost_%'"
        ).fetchone()[0] == 1  # Only the retired removal-jobs table exists at startup.
    with db.get_conn() as conn:
        status.initialize_status_schema(conn)
        conn.executemany(
            "INSERT INTO users (google_id, email, role) VALUES (?, ?, ?)",
            (("account-a", "a@example.com", "admin"),
             ("account-b", "b@example.com", "user")),
        )
    yield app, db, status, database
    for name in tuple(sys.modules):
        if name == "db" or name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def _subject(db, status, owner, relationship="self"):
    with db.get_conn() as conn:
        subject = status.create_subject(conn, owner, {"relationship": relationship})
        consent = {"accepted": True}
        if relationship == "family":
            consent["familyAuthorityAttested"] = True
        status.record_consent(conn, owner, subject["subjectId"], consent)
    return subject["subjectId"]


def _event(db, status, owner, subject_id, broker, event, revision, **extra):
    with db.get_conn() as conn:
        return status.apply_client_event(
            conn, owner, broker,
            {"subjectId": subject_id, "event": event, "expectedRevision": revision, **extra},
            source="manual",
        )


def test_schema_has_no_person_profile_or_listing_columns(foundation):
    _, _, _, database = foundation
    with sqlite3.connect(database) as conn:
        for table in ("go_ghost_subjects", "go_ghost_consents", "go_ghost_requests"):
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            assert columns.isdisjoint({
                "name", "first_name", "last_name", "email", "phone", "address",
                "birth_year", "profile", "listing_url", "target_url", "detail",
            })
        assert {row[1] for row in conn.execute("PRAGMA table_info(go_ghost_requests)")} >= {
            "user_id", "subject_id", "broker_id", "revision", "source", "state",
        }


def test_admin_routing_cannot_read_or_write_another_accounts_subject(foundation):
    _, db, status, _ = foundation
    own = _subject(db, status, "account-a")
    other = _subject(db, status, "account-b")
    token = db.set_rls_context("account-a", "admin", "a@example.com")
    try:
        with db.get_conn() as conn:
            # The generic helper bypasses owner filtering for admins, so the
            # Go Ghost data layer must use an explicit account predicate.
            assert len(db.user_scoped_select(conn, "go_ghost_subjects")) == 2
            assert [item["subjectId"] for item in status.list_status(conn, "account-a")] == [own]
            with pytest.raises(status.SubjectNotFoundError):
                status.apply_client_event(
                    conn, "account-a", "intelius",
                    {"subjectId": other, "event": "mark_submitted", "expectedRevision": 0},
                    source="manual",
                )
    finally:
        db.reset_rls_context(token)
    with db.get_conn() as conn:
        assert status.list_status(conn, "account-b")[0]["requests"] == []


def test_family_attestation_and_version_are_required(foundation):
    _, db, status, _ = foundation
    with db.get_conn() as conn:
        family = status.create_subject(conn, "account-a", {"relationship": "family"})["subjectId"]
    with db.get_conn() as conn:
        with pytest.raises(status.StatusValidationError):
            status.record_consent(conn, "account-a", family, {"accepted": True})
    with db.get_conn() as conn:
        consent = status.record_consent(
            conn, "account-a", family,
            {"accepted": True, "familyAuthorityAttested": True},
        )
        assert consent["version"] == status.CONSENT_VERSION
        assert consent["familyAuthorityAttestedAt"] == consent["acceptedAt"]
        with pytest.raises(status.StatusValidationError):
            status.record_consent(conn, "account-a", family,
                                  {"accepted": True, "familyAuthorityAttested": True,
                                   "email": "someone@example.com"})


def test_only_one_self_subject_per_account_is_enforced_in_storage(foundation):
    _, db, status, _ = foundation
    first = _subject(db, status, "account-a")
    with db.get_conn() as conn:
        with pytest.raises(status.StatusConflictError):
            status.create_subject(conn, "account-a", {"relationship": "self"})
    with db.get_conn() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO go_ghost_subjects
                   (subject_id, user_id, relationship, created_at) VALUES (?, ?, 'self', ?)""",
                ("ea82f92c-6675-4b69-b330-951ace9db09a", "account-a", "2026-11-14T00:00:00Z"),
            )
    with db.get_conn() as conn:
        assert [item["subjectId"] for item in status.list_status(conn, "account-a")] == [first]


def test_event_validation_revisions_and_claim_provenance(foundation):
    _, db, status, _ = foundation
    subject = _subject(db, status, "account-a")
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", subject, "intelius", "verified_removed", 0)
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", subject, "intelius", "mark_submitted", 0,
               name="Somebody", listingUrl="https://example.com/person")
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", subject, "intelius", "mark_submitted", 0,
               recipeVersion="person-name")
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", subject, "intelius", "mark_submitted", True)
    submitted = _event(db, status, "account-a", subject, "intelius", "mark_submitted", 0)
    assert submitted["state"] == "submitted"
    assert submitted["nextCheckAt"] is not None
    with pytest.raises(status.StatusConflictError):
        _event(db, status, "account-a", subject, "intelius", "begin_recheck", 0)
    checking = _event(db, status, "account-a", subject, "intelius", "begin_recheck", 1)
    reported = _event(db, status, "account-a", subject, "intelius", "recheck_absent", 2)
    assert checking["state"] == "verifying"
    assert reported["state"] == "client_recheck_absent"
    assert reported["state"] != "verified_removed"
    assert reported["source"] == "manual"
    with pytest.raises(status.StatusConflictError):
        _event(db, status, "account-a", subject, "intelius", "scan_found", 3)
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", subject, "intelius", "mark_failed", 3,
               failureCode="Some freeform failure text")


def test_broker_id_not_parent_group_is_status_key(foundation):
    _, db, status, _ = foundation
    subject = _subject(db, status, "account-a")
    _event(db, status, "account-a", subject, "intelius", "mark_submitted", 0)
    with db.get_conn() as conn:
        requests = status.list_status(conn, "account-a")[0]["requests"]
    assert [item["broker_id"] for item in requests] == ["intelius"]
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", subject, "peopleconnect", "mark_submitted", 0)


def test_family_subject_cannot_update_self_only_peopleconnect_broker(foundation):
    _, db, status, _ = foundation
    family = _subject(db, status, "account-a", "family")
    with pytest.raises(status.StatusValidationError):
        _event(db, status, "account-a", family, "intelius", "mark_submitted", 0)
    allowed = _event(db, status, "account-a", family, "fastpeoplesearch", "mark_submitted", 0)
    assert allowed["state"] == "submitted"


def test_export_and_erasure_include_all_go_ghost_rows(foundation):
    app, db, status, database = foundation
    a = _subject(db, status, "account-a")
    b = _subject(db, status, "account-b")
    _event(db, status, "account-a", a, "intelius", "mark_submitted", 0)
    _event(db, status, "account-b", b, "truthfinder", "mark_submitted", 0)
    with db.get_conn() as conn:
        conn.execute(
            """INSERT INTO go_ghost_removal_jobs
               (id, user_id, email, broker, status, detail, target_url, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old-job-a", "account-a", "a@example.com", "intelius", "done",
             "old detail", "https://example.com/old", "2026-11-14", "2026-11-14"),
        )
    exported = app.get_user_export("a@example.com", "account-a")
    assert len(exported["goGhostSubjects"]) == 1
    assert len(exported["goGhostConsents"]) == 1
    assert len(exported["goGhostRequests"]) == 1
    assert len(exported["goGhostLegacyJobs"]) == 1
    assert all(row["user_id"] == "account-a" for key in (
        "goGhostSubjects", "goGhostConsents", "goGhostRequests", "goGhostLegacyJobs"
    ) for row in exported[key])
    assert app.delete_user_data("a@example.com", "account-a") is True
    with sqlite3.connect(database) as conn:
        for table in ("go_ghost_subjects", "go_ghost_consents",
                      "go_ghost_requests", "go_ghost_removal_jobs"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE user_id = 'account-a'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM go_ghost_requests WHERE user_id = 'account-b'").fetchone()[0] == 1


def test_http_status_routes_stay_disabled_even_with_environment_switch(foundation):
    app, _, status, database = foundation
    assert status.GO_GHOST_STATUS_SYNC_AVAILABLE is False
    client = TestClient(app.qr_app, base_url="https://testserver")
    for method, path in (
        ("GET", "/api/go-ghost/status"),
        ("POST", "/api/go-ghost/subjects"),
        ("POST", "/api/go-ghost/subjects/subject/consent"),
        ("PUT", "/api/go-ghost/status/intelius"),
    ):
        response = client.request(method, path, json={"name": "Cannot reach storage"})
        assert response.status_code == 503
        assert response.headers["Cache-Control"] == "no-store"
    with sqlite3.connect(database) as conn:
        for table in ("go_ghost_subjects", "go_ghost_consents", "go_ghost_requests"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_legal_access_and_erasure_tolerate_status_tables_not_yet_created(foundation):
    app, _, _, database = foundation
    with sqlite3.connect(database) as conn:
        for table in ("go_ghost_requests", "go_ghost_consents", "go_ghost_subjects"):
            conn.execute(f"DROP TABLE {table}")
    exported = app.get_user_export("a@example.com", "account-a")
    assert exported["goGhostSubjects"] == []
    assert exported["goGhostConsents"] == []
    assert exported["goGhostRequests"] == []
    assert app.delete_user_data("a@example.com", "account-a") is True
