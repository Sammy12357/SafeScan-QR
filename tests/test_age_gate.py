"""The age decision must precede account creation and session issuance."""

import importlib
import sqlite3
import sys
from datetime import date, datetime, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def age_app(tmp_path, monkeypatch):
    db_path = tmp_path / "age.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("PRIVACY_HASH_SALT", "age-test-secret")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("TOKEN_FEATURES_ENABLED", "true")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    app.RATE_LIMITS.clear()
    monkeypatch.setattr(routes, "run_fraud_checks", lambda *args, **kwargs: [])

    def google_token(token, transport, client_id):
        return {"sub": "google-1", "email": "person@example.com", "email_verified": True,
                "name": "Person"}

    monkeypatch.setattr(routes.id_token, "verify_oauth2_token", google_token)
    yield app, routes, db_path
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def rows(db_path, table):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"SELECT * FROM {table}").fetchall()


def start_google(client):
    return client.post("/auth/google", data={"credential": "verified-id-token", "next": "/profile"},
                       follow_redirects=False)


def year_at_least(age):
    return str(datetime.now(timezone.utc).year - age - 1)


def accepted_web_age(**extra):
    return {"birth_year": year_at_least(20), "birthday_this_year": "yes",
            "legal_consent": "yes", "terms_version": "v1.1", "privacy_version": "v1.1", **extra}


def accepted_mobile_age(ticket, **extra):
    return {"ageTicket": ticket, "birthYear": year_at_least(20),
            "birthdayThisYear": "yes", "legalConsent": True,
            "termsVersion": "v1.1", "privacyVersion": "v1.1", **extra}


def test_web_google_requires_one_time_age_decision_before_account_or_session(age_app):
    app, _, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    start = start_google(client)
    assert start.status_code == 303
    assert start.headers["location"] == "/auth/confirm-age"
    assert "__Host-safescan_pending_age" in client.cookies
    assert rows(db_path, "users") == []
    assert rows(db_path, "sessions") == []
    assert rows(db_path, "persistent_sessions") == []

    form = client.get("/auth/confirm-age")
    assert form.status_code == 200
    assert "email\"" not in form.text
    assert 'name="threshold"' not in form.text
    assert "What year were you born?" in form.text
    completed = client.post("/auth/confirm-age", data=accepted_web_age(
        email="attacker@example.com", threshold="0", locale="en-US"), follow_redirects=False)
    assert completed.status_code == 303
    assert completed.headers["location"] == "/profile"
    assert len(rows(db_path, "users")) == 1
    assert len(rows(db_path, "sessions")) == 1
    assert len(rows(db_path, "age_eligibility")) == 1
    assert rows(db_path, "age_confirmations") == []
    assert client.get("/api/me").status_code == 200
    export = app.get_user_export("person@example.com", "google-1")
    assert export["ageEligibility"][0]["minimum_age"] == 16
    assert client.post("/auth/confirm-age", data={"birth_year": year_at_least(20),
                                                    "birthday_this_year": "yes"}).status_code == 410


def test_underage_cannot_create_account_or_retry_with_tampered_threshold(age_app):
    app, _, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    assert start_google(client).status_code == 303
    underage = client.post("/auth/confirm-age", data={
        "birth_year": str(datetime.now(timezone.utc).year - 10),
        "birthday_this_year": "yes", "threshold": "0", "email": "attacker@example.com",
    })
    assert underage.status_code == 403
    assert rows(db_path, "users") == []
    assert rows(db_path, "sessions") == []
    assert rows(db_path, "pending_age_signins") == []
    assert len(rows(db_path, "age_denials")) == 1
    assert start_google(client).status_code == 409
    # The same Google identity cannot immediately retry through the mobile path.
    assert client.post("/auth/verify", json={"token": "verified-id-token"}).status_code == 409
    assert client.post("/auth/confirm-age", data={"birth_year": year_at_least(20),
                                                    "birthday_this_year": "yes"}).status_code == 410


def test_neutral_year_check_handles_birthday_boundary_without_storing_date(age_app):
    app, _, db_path = age_app
    age_gate = importlib.import_module("hackabull.age_gate")
    assert age_gate.age_from_year("2010", "no", today=date(2026, 11, 15)) == 15
    assert age_gate.age_from_year("2010", "yes", today=date(2026, 11, 15)) == 16
    assert age_gate.age_from_year("2008", "no", today=date(2026, 11, 15)) == 17
    assert age_gate.age_from_year("2008", "yes", today=date(2026, 11, 15)) == 18
    with pytest.raises(ValueError):
        age_gate.age_from_year("2010", "unknown", today=date(2026, 11, 15))
    assert "birth_year" not in {row[1] for row in sqlite3.connect(db_path).execute("PRAGMA table_info(age_eligibility)")}


def test_verified_identity_cannot_claim_another_accounts_email(age_app):
    app, _, db_path = age_app
    existing_id = app.save_user_to_db("original-sub", "person@example.com")
    importlib.import_module("hackabull.age_gate").record_account_eligibility(existing_id)
    client = TestClient(app.qr_app, base_url="https://testserver")
    response = start_google(client)
    assert response.status_code == 409
    assert len(rows(db_path, "users")) == 1
    assert rows(db_path, "pending_age_signins") == []


def test_mobile_google_and_auth0_require_ticket_and_reject_replay(age_app, monkeypatch):
    app, routes, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    first = client.post("/auth/verify", json={"token": "google-token"})
    assert first.status_code == 202
    assert first.json()["ageConfirmationRequired"] is True
    assert "session" not in first.json()
    assert rows(db_path, "users") == []
    ticket = first.json()["ageTicket"]
    invalid = client.post("/auth/confirm-age/mobile", json={
        "ageTicket": ticket, "birthYear": "not-a-year", "birthdayThisYear": "yes"})
    assert invalid.status_code == 400
    complete = client.post("/auth/confirm-age/mobile", json=accepted_mobile_age(ticket))
    assert complete.status_code == 200
    assert complete.json()["session"]
    assert complete.json()["user"]["email"] == "person@example.com"
    assert client.post("/auth/confirm-age/mobile", json=accepted_mobile_age(ticket)).status_code == 410
    assert client.post("/auth/verify", json={"token": "google-token"}).status_code == 200

    monkeypatch.setattr(routes, "_decode_jwt_unverified", lambda token: ({}, {"iss": app.AUTH0_ISSUER}, []))
    monkeypatch.setattr(routes, "verify_auth0_id_token", lambda token: {
        "sub": "github|different-person", "email": "other@example.com", "email_verified": True,
    })
    auth0 = client.post("/auth/verify", json={"token": "auth0-token"})
    assert auth0.status_code == 202
    assert rows(db_path, "users")[0][0] == "google-1"
    confirmed = client.post("/auth/confirm-age/mobile", json=accepted_mobile_age(auth0.json()["ageTicket"]))
    assert confirmed.status_code == 200
    assert confirmed.json()["user"]["id"] == "auth0:github|different-person"


def test_existing_sessions_and_legacy_email_confirmation_do_not_bypass_gate(age_app):
    app, _, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    user_id = app.save_user_to_db("google-1", "person@example.com")
    with app.get_conn() as conn:
        conn.execute("INSERT INTO age_confirmations VALUES (?, ?, ?, ?)",
                     ("person@example.com", 99, "en-US", "2026-01-01T00:00:00Z"))
    from starlette.requests import Request
    fake_request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    session_id = app.create_session(user_id, fake_request)
    client.cookies.set(app.SESSION_COOKIE_NAME, session_id)
    assert client.get("/api/me").status_code == 401
    assert len(rows(db_path, "users")) == 1
    assert start_google(client).status_code == 303
    assert len(rows(db_path, "users")) == 1
    done = client.post("/auth/confirm-age", data=accepted_web_age(), follow_redirects=False)
    assert done.status_code == 303
    assert client.get("/api/me").status_code == 200


def test_adult_gate_covers_guest_payment_and_account_wallet(age_app):
    app, _, db_path = age_app
    gate = importlib.import_module("hackabull.app_module")._requires_adult_attestation
    assert gate("/pay/alpha")
    assert gate("/pay/alpha/solana/verify")
    assert not gate("/pay/alpha/manage")
    assert not gate("/pay/alpha/success")
    assert not gate("/webhooks/stripe")
    guest = TestClient(app.qr_app, base_url="https://testserver")
    blocked = guest.get("/pay/alpha", follow_redirects=False)
    assert blocked.status_code == 303
    assert blocked.headers["location"].startswith("/auth/confirm-adult")
    assert guest.get(blocked.headers["location"]).status_code == 200
    younger = guest.post("/auth/confirm-adult", data={
        "birth_year": str(datetime.now(timezone.utc).year - 17),
        "birthday_this_year": "yes", "adult_attestation": "yes"})
    assert younger.status_code == 403
    assert guest.get("/pay/alpha", follow_redirects=False).status_code == 303
    assert guest.get("/auth/confirm-adult?next=/pay/alpha").status_code == 200
    adult = guest.post("/auth/confirm-adult", data={
        "birth_year": year_at_least(20), "birthday_this_year": "yes",
        "adult_attestation": "yes"}, follow_redirects=False)
    assert adult.status_code == 303
    assert adult.headers["location"] == "/pay/alpha"
    assert guest.get("/pay/alpha").status_code == 200
    assert guest.get("/go-ghost").status_code == 200

    signed = TestClient(app.qr_app, base_url="https://testserver")
    assert start_google(signed).status_code == 303
    assert signed.post("/auth/confirm-age", data=accepted_web_age(),
        follow_redirects=False).status_code == 303
    assert signed.get("/api/wallet").status_code == 403
    assert signed.get("/token", follow_redirects=False).status_code == 303
    assert signed.get("/auth/confirm-adult?next=/token").status_code == 200
    assert signed.post("/auth/confirm-adult", data={
        "birth_year": year_at_least(20), "birthday_this_year": "yes",
        "adult_attestation": "yes"}, follow_redirects=False).status_code == 303
    assert signed.get("/token").status_code == 200
    assert signed.get("/api/wallet").status_code == 200
    assert rows(db_path, "age_eligibility")[0][1] == 18


def test_mobile_adult_ticket_is_account_bound_one_time_and_requires_18(age_app):
    app, _, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    first = client.post("/auth/verify", json={"token": "verified-id-token"})
    session = client.post("/auth/confirm-age/mobile", json=accepted_mobile_age(first.json()["ageTicket"])).json()["session"]
    headers = {"Authorization": f"Bearer {session}"}
    blocked = client.get("/api/wallet", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["minimumAge"] == 18
    assert "session" not in blocked.json()
    ticket = blocked.json()["ageTicket"]

    # A second, eligible account cannot redeem another account's ticket.
    other_id = app.save_user_to_db("google-2", "other@example.com")
    age_gate = importlib.import_module("hackabull.age_gate")
    age_gate.record_account_eligibility(other_id)
    from starlette.requests import Request
    fake_request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    other_session = app.create_session(other_id, fake_request)
    wrong_account = client.post("/auth/confirm-adult/mobile", headers={
        "Authorization": f"Bearer {other_session}"}, json={
            "ageTicket": ticket, "birthYear": year_at_least(20),
            "birthdayThisYear": "yes", "adultAttestation": True})
    assert wrong_account.status_code == 410

    underage = client.post("/auth/confirm-adult/mobile", headers=headers, json={
        "ageTicket": ticket, "birthYear": str(datetime.now(timezone.utc).year - 17),
        "birthdayThisYear": "yes", "adultAttestation": True})
    assert underage.status_code == 403
    assert client.post("/auth/confirm-adult/mobile", headers=headers, json={
        "ageTicket": ticket, "birthYear": year_at_least(20),
        "birthdayThisYear": "yes", "adultAttestation": True}).status_code == 410
    assert client.get("/api/wallet", headers=headers).status_code == 403

    fresh_ticket = client.get("/api/wallet", headers=headers).json()["ageTicket"]
    adult = client.post("/auth/confirm-adult/mobile", headers=headers, json={
        "ageTicket": fresh_ticket, "birthYear": year_at_least(20),
        "birthdayThisYear": "yes", "adultAttestation": True})
    assert adult.status_code == 200
    assert adult.json() == {"adultConfirmed": True}
    assert client.get("/api/wallet", headers=headers).status_code == 200
    assert len(rows(db_path, "age_eligibility")) == 2


def test_account_requires_explicit_current_agreement_before_session(age_app):
    app, _, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    assert start_google(client).headers["location"] == "/auth/confirm-age"
    form = client.get("/auth/confirm-age")
    assert 'name="legal_consent"' in form.text
    assert 'name="legal_consent" value="yes" required' in form.text
    assert "/legal/terms-of-use" in form.text and "/legal/privacy-policy" in form.text
    missing = client.post("/auth/confirm-age", data={
        "birth_year": year_at_least(20), "birthday_this_year": "yes",
        "terms_version": "v1.1", "privacy_version": "v1.1",
    })
    assert missing.status_code == 400
    assert rows(db_path, "users") == []
    assert rows(db_path, "sessions") == []
    stale = client.post("/auth/confirm-age", data=accepted_web_age(privacy_version="v1.0"))
    assert stale.status_code == 400
    assert rows(db_path, "users") == []
    accepted = client.post("/auth/confirm-age", data=accepted_web_age(), follow_redirects=False)
    assert accepted.status_code == 303
    proof = rows(db_path, "terms_acceptances")
    assert {(row[1], row[2]) for row in proof} == {("terms", "v1.1"), ("privacy", "v1.1")}
    assert all(len(row[4]) == 64 for row in proof)
    exported = app.get_user_export("person@example.com", "google-1")
    assert len(exported["termsAcceptances"]) == 2


def test_existing_web_user_reaccepts_updated_documents_with_one_time_ticket(age_app):
    app, _, db_path = age_app
    first = TestClient(app.qr_app, base_url="https://testserver")
    start_google(first)
    assert first.post("/auth/confirm-age", data=accepted_web_age(), follow_redirects=False).status_code == 303
    with app.get_conn() as conn:
        conn.execute("DELETE FROM terms_acceptances WHERE user_id = ? AND document = 'privacy'", ("google-1",))
    second = TestClient(app.qr_app, base_url="https://testserver")
    sessions_before = len(rows(db_path, "sessions"))
    pending = start_google(second)
    assert pending.status_code == 303
    assert pending.headers["location"] == "/auth/accept-terms"
    assert "__Host-safescan_pending_terms" in second.cookies
    assert len(rows(db_path, "sessions")) == sessions_before
    assert second.get("/api/me").status_code == 401
    page = second.get("/auth/accept-terms")
    assert page.status_code == 200
    assert 'name="legal_consent" value="yes" required' in page.text
    assert second.post("/auth/accept-terms", data={
        "terms_version": "v1.1", "privacy_version": "v1.1"
    }).status_code == 400
    completed = second.post("/auth/accept-terms", data={
        "terms_version": "v1.1", "privacy_version": "v1.1", "legal_consent": "yes"
    }, follow_redirects=False)
    assert completed.status_code == 303
    assert second.get("/api/me").status_code == 200
    assert len(rows(db_path, "sessions")) == sessions_before + 1
    assert second.post("/auth/accept-terms", data={
        "terms_version": "v1.1", "privacy_version": "v1.1", "legal_consent": "yes"
    }).status_code == 410


def test_existing_mobile_user_gets_terms_challenge_without_session(age_app):
    app, _, db_path = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    first = client.post("/auth/verify", json={"token": "verified-id-token"})
    assert client.post("/auth/confirm-age/mobile", json=accepted_mobile_age(first.json()["ageTicket"])).status_code == 200
    with app.get_conn() as conn:
        conn.execute("DELETE FROM terms_acceptances WHERE user_id = ? AND document = 'terms'", ("google-1",))
    pending = client.post("/auth/verify", json={"token": "verified-id-token"})
    assert pending.status_code == 202
    body = pending.json()
    assert body["termsAcceptanceRequired"] is True
    assert body["termsVersion"] == body["privacyVersion"] == "v1.1"
    assert "session" not in body
    ticket = body["termsTicket"]
    refused = client.post("/auth/accept-terms/mobile", json={
        "termsTicket": ticket, "legalConsent": False,
        "termsVersion": "v1.1", "privacyVersion": "v1.1",
    })
    assert refused.status_code == 400
    stale = client.post("/auth/accept-terms/mobile", json={
        "termsTicket": ticket, "legalConsent": True,
        "termsVersion": "v1.1", "privacyVersion": "v1.0",
    })
    assert stale.status_code == 400
    accepted = client.post("/auth/accept-terms/mobile", json={
        "termsTicket": ticket, "legalConsent": True,
        "termsVersion": "v1.1", "privacyVersion": "v1.1",
    })
    assert accepted.status_code == 200
    assert accepted.json()["session"]
    assert client.post("/auth/accept-terms/mobile", json={
        "termsTicket": ticket, "legalConsent": True,
        "termsVersion": "v1.1", "privacyVersion": "v1.1",
    }).status_code == 410
    assert len(rows(db_path, "terms_acceptances")) == 2


def test_document_archive_is_versioned_and_rejects_unknown_versions(age_app):
    app, _, _ = age_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    old = client.get("/legal/documents/terms/v1.0")
    current = client.get("/legal/terms-of-use")
    assert old.status_code == current.status_code == 200
    assert "Archived source snapshot" in old.text
    assert "at least 13 globally" in old.text
    assert "age 16 or older" in current.text
    assert "Version v1.1" in current.text
    assert client.get("/legal/documents/terms/v9.9").status_code == 404
    assert client.get("/legal/documents/unknown/v1.0").status_code == 404
