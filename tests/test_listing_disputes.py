"""Public listing correction flow and its privacy/evidence boundary."""

import importlib
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def listing_app(tmp_path, monkeypatch):
    db_path = tmp_path / "listing.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("OWNER_EMAILS", "owner@example.com")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.delenv("SMTP_HOST", raising=False)
    [sys.modules.pop(name, None) for name in list(sys.modules)
     if name == "hackabull" or name.startswith("hackabull.")]
    sys.modules.pop("db", None)
    module = importlib.import_module("hackabull")
    monkeypatch.setattr(importlib.import_module("hackabull.routes_scan_auth"), "LOCAL_AUTH_ENABLED", True)
    module.RATE_LIMITS.clear()
    client = TestClient(module.qr_app, base_url="https://testserver")
    yield module, client, db_path
    [sys.modules.pop(name, None) for name in list(sys.modules)
     if name == "hackabull" or name.startswith("hackabull.")]
    sys.modules.pop("db", None)


def seed_blocklist(db_path, *urls):
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO url_blocklist (id, url, reason, added_by, created_at) VALUES (?, ?, ?, ?, ?)",
            [(f"block-{index}", url, "Original administrator record", "admin@example.com",
              f"2026-11-10T10:00:0{index}Z") for index, url in enumerate(urls)],
        )


def rows(db_path, query, params=()):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query, params)]


def submit(client, listing_id, **overrides):
    values = {
        "contact_email": "operator@example.net",
        "claim": "This URL observation appears to involve a compromised page that has now been removed.",
        "website": "",
    }
    values.update(overrides)
    return client.post(f"/malicious-database/dispute/{listing_id}", data=values, follow_redirects=False)


def admin_login(client):
    response = client.post("/auth/register", data={"email": "admin@example.com", "password": "password123"})
    assert response.status_code in (200, 303)


def test_public_listing_uses_observed_wording_and_keeps_private_data_private(listing_app):
    _, client, db_path = listing_app
    seed_blocklist(db_path, "https://example.com/reset?token=SECRET_VALUE")
    feed = client.get("/api/malicious-qr")
    page = client.get("/malicious-database")

    assert feed.status_code == 200
    entry = feed.json()["entries"][0]
    assert entry["domain"] == "example.com"
    assert entry["category"] == "Administrator listing record"
    assert entry["evidenceSource"] == "SafeScan administrator listing record"
    assert entry["underReview"] is False
    assert "SECRET_VALUE" not in feed.text
    assert "reset" not in feed.text
    assert "Malicious QR Database" not in page.text
    assert "A listing does not describe every page" in page.text
    assert client.get("/malicious-database/policy").status_code == 200


def test_dispute_form_marks_listing_under_review_without_publishing_claim_or_email(listing_app):
    _, client, db_path = listing_app
    seed_blocklist(db_path, "https://example.com/private?token=SECRET_VALUE")
    listing_id = client.get("/api/malicious-qr").json()["entries"][0]["id"]
    form = client.get(f"/malicious-database/dispute/{listing_id}")
    assert form.status_code == 200
    assert "Dispute this listing" in form.text
    assert "SECRET_VALUE" not in form.text
    assert client.get(f"/admin/listings/{listing_id}").status_code == 401

    response = submit(client, listing_id, claim="This is a false positive for our business; please review the evidence.")
    assert response.status_code == 303
    assert response.headers["location"].endswith("?submitted=1")
    saved = rows(db_path, "SELECT * FROM listing_disputes")
    assert len(saved) == 1
    assert saved[0]["status"] == "under_review"
    feed = client.get("/api/malicious-qr")
    assert feed.json()["entries"][0]["underReview"] is True
    assert "operator@example.net" not in feed.text
    assert "false positive" not in feed.text
    assert "SECRET_VALUE" not in feed.text


def test_dispute_submission_rejects_invalid_and_oversized_input_and_honeypot(listing_app):
    _, client, db_path = listing_app
    seed_blocklist(db_path, "https://example.com/path")
    listing_id = client.get("/api/malicious-qr").json()["entries"][0]["id"]
    invalid = submit(client, listing_id, contact_email="bad\nemail@example.net")
    assert invalid.status_code == 400
    assert "Enter a valid contact email" in invalid.text
    oversized = client.post(
        f"/malicious-database/dispute/{listing_id}",
        content="claim=" + "x" * 9000,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert oversized.status_code == 413
    bot = submit(client, listing_id, website="spam.example")
    assert bot.status_code == 303
    assert rows(db_path, "SELECT * FROM listing_disputes") == []
    limited = submit(client, listing_id)
    assert limited.status_code == 429


def test_cross_origin_dispute_post_is_blocked(listing_app):
    _, client, db_path = listing_app
    seed_blocklist(db_path, "https://example.com/path")
    listing_id = client.get("/api/malicious-qr").json()["entries"][0]["id"]
    denied = client.post(f"/malicious-database/dispute/{listing_id}", data={
        "contact_email": "operator@example.net",
        "claim": "The listing is inaccurate and the underlying page was removed.",
    }, headers={"Origin": "https://attacker.example"})
    assert denied.status_code == 403
    assert rows(db_path, "SELECT * FROM listing_disputes") == []


def test_user_report_alone_cannot_publish_and_admin_must_record_evidence(listing_app):
    _, client, db_path = listing_app
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO url_reports (id, url, reporter_email, reason, risk_score, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            ("report-1", "https://example.com/login?token=PRIVATE", "reporter@example.net",
             "I think this is phishing", 85, "2026-11-10T10:00:00Z"),
        )
    assert client.get("/api/malicious-qr").json()["total"] == 0
    admin_login(client)
    no_evidence = client.post("/admin/reports/report-1/action", data={"action": "confirm"})
    assert no_evidence.status_code == 400
    assert "Record the independent review" in no_evidence.text
    assert client.get("/api/malicious-qr").json()["total"] == 0

    reviewed = client.post("/admin/reports/report-1/action", data={
        "action": "confirm", "evidence_source": "admin_review",
        "observation": "Administrator independently observed a credential collection prompt.",
    }, follow_redirects=False)
    assert reviewed.status_code == 303
    evidence = rows(db_path, "SELECT source, source_ref, observation FROM listing_evidence")
    assert evidence == [{"source": "admin_review", "source_ref": "report-1",
                         "observation": "Administrator independently observed a credential collection prompt."}]
    feed = client.get("/api/malicious-qr")
    assert feed.json()["entries"][0]["evidenceSource"] == "SafeScan administrator review"
    assert feed.json()["entries"][0]["observedAt"] == rows(db_path, "SELECT observed_at FROM listing_evidence")[0]["observed_at"]
    assert "reporter@example.net" not in feed.text
    assert "PRIVATE" not in feed.text


def test_admin_dispute_decision_removes_every_domain_record_immediately(listing_app):
    _, client, db_path = listing_app
    seed_blocklist(db_path, "https://example.com/first?token=ONE", "https://example.com/second?token=TWO")
    listing_id = client.get("/api/malicious-qr").json()["entries"][0]["id"]
    assert submit(client, listing_id).status_code == 303
    admin_login(client)
    detail = client.get(f"/admin/listings/{listing_id}")
    assert detail.status_code == 200
    assert "operator@example.net" in detail.text
    assert "Original administrator record" in detail.text
    dispute_id = rows(db_path, "SELECT id FROM listing_disputes")[0]["id"]
    missing_reason = client.post(f"/admin/listing-disputes/{dispute_id}/action", data={"action": "remove"})
    assert missing_reason.status_code == 400
    assert client.get("/api/malicious-qr").json()["total"] == 1

    decision = client.post(f"/admin/listing-disputes/{dispute_id}/action", data={
        "action": "remove", "decision_reason": "The observation is no longer supported by the reviewed evidence.",
    }, follow_redirects=False)
    assert decision.status_code == 303
    assert client.get("/api/malicious-qr").json()["total"] == 0
    assert rows(db_path, "SELECT COUNT(*) AS total FROM url_blocklist WHERE removed_at IS NULL")[0]["total"] == 0
    dispute = rows(db_path, "SELECT status, decision_reason, decided_at FROM listing_disputes")[0]
    assert dispute["status"] == "removed"
    assert dispute["decision_reason"] == "The observation is no longer supported by the reviewed evidence."
    assert dispute["decided_at"]


def test_admin_can_acknowledge_and_retain_with_reason(listing_app):
    _, client, db_path = listing_app
    seed_blocklist(db_path, "https://example.com/path")
    listing_id = client.get("/api/malicious-qr").json()["entries"][0]["id"]
    assert submit(client, listing_id).status_code == 303
    dispute_id = rows(db_path, "SELECT id FROM listing_disputes")[0]["id"]
    admin_login(client)
    acknowledged = client.post(f"/admin/listing-disputes/{dispute_id}/action", data={
        "action": "acknowledge",
    }, follow_redirects=False)
    assert acknowledged.status_code == 303
    assert rows(db_path, "SELECT first_reviewed_at FROM listing_disputes")[0]["first_reviewed_at"]
    decision = {
        "action": "retain", "decision_reason": "The documented QR URL observation remains supported by staff review.",
    }
    legacy_without_evidence = client.post(
        f"/admin/listing-disputes/{dispute_id}/action", data=decision,
    )
    assert legacy_without_evidence.status_code == 400
    assert rows(db_path, "SELECT status FROM listing_disputes")[0]["status"] == "under_review"
    evidence_added = client.post(f"/admin/listings/{listing_id}/evidence", data={
        "block_id": "block-0", "evidence_source": "admin_review",
        "observation": "Administrator independently verified that the QR URL still requests credentials.",
    }, follow_redirects=False)
    assert evidence_added.status_code == 303
    retained = client.post(f"/admin/listing-disputes/{dispute_id}/action", data=decision, follow_redirects=False)
    assert retained.status_code == 303
    assert rows(db_path, "SELECT status FROM listing_disputes")[0]["status"] == "retained"
    feed = client.get("/api/malicious-qr").json()
    assert feed["total"] == 1
    assert feed["entries"][0]["underReview"] is False


def test_dispute_target_skips_weekends(listing_app):
    module, _, _ = listing_app
    assert module.first_response_due("2026-11-13T12:00:00Z") == "2026-11-17"  # Friday → Tuesday
