"""Consent and suppression are enforced before product-update delivery."""

from __future__ import annotations

import importlib
import re
import sqlite3
import sys
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient


class FakeSMTP:
    messages = []
    fail = False

    def __init__(self, host, port, timeout):
        assert (host, port, timeout) == ("mail.test", 587, 15)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def starttls(self):
        pass

    def login(self, username, password):
        assert (username, password) == ("mailer", "mailer-secret")

    def send_message(self, message, from_addr, to_addrs):
        if self.fail:
            raise RuntimeError("recipient@example.com token-should-not-appear")
        assert from_addr == "updates@sqafe.com"
        self.messages.append(message)


@pytest.fixture()
def mail_app(tmp_path, monkeypatch):
    db_path = tmp_path / "mail.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SMTP_HOST", "mail.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "mailer")
    monkeypatch.setenv("SMTP_PASSWORD", "mailer-secret")
    monkeypatch.setenv("EMAIL_FROM", "updates@sqafe.com")
    monkeypatch.setenv("EMAIL_TOKEN_SECRET", "test-secret-" + "x" * 40)
    monkeypatch.delenv("COMPANY_LEGAL_NAME", raising=False)
    monkeypatch.delenv("COMPANY_POSTAL_ADDRESS", raising=False)
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    email_util = importlib.import_module("hackabull.email_util")
    waitlist = importlib.import_module("hackabull.waitlist_email")
    FakeSMTP.messages = []
    FakeSMTP.fail = False
    monkeypatch.setattr(email_util.smtplib, "SMTP", FakeSMTP)
    yield app, TestClient(app.qr_app, base_url="https://testserver", raise_server_exceptions=False), db_path, email_util, waitlist
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def _token(message):
    html = message.get_body(preferencelist=("html",)).get_content()
    url = re.search(r'href="([^"]+)"', html).group(1)
    return parse_qs(urlparse(url).query)["token"][0]


def _rows(db_path, query, args=()):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query, args)]


def _request(client, email="recipient@example.com"):
    return client.post("/waitlist", data={"email": email, "consent": "yes", "source": "footer"}, follow_redirects=False)


def test_public_form_and_consent_banner_describe_actual_flow(mail_app):
    _, client, _, _, _ = mail_app
    page = client.get("/waitlist")
    assert page.status_code == 200
    assert 'name="consent" value="yes" required' in page.text
    assert "Your address joins the list only after you confirm it" in page.text
    assert "first-party scanner performance counts" in page.text
    assert "non-essential tracking" not in page.text


def test_unconfigured_waitlist_and_missing_consent_do_not_store_address(mail_app, monkeypatch):
    _, client, db_path, email_util, _ = mail_app
    assert client.post("/waitlist", data={"email": "recipient@example.com"}).status_code == 400
    monkeypatch.setattr(email_util, "SMTP_HOST", "")
    unavailable = _request(client)
    assert unavailable.status_code == 503
    assert "Email updates are unavailable" in unavailable.text
    assert not _rows(db_path, "SELECT * FROM waitlist_signups")
    assert not FakeSMTP.messages


def test_sender_rejects_unclassified_and_unguarded_marketing(mail_app):
    _, _, _, email_util, _ = mail_app
    with pytest.raises(ValueError, match="Unknown email template"):
        email_util.send_email("recipient@example.com", "Subject", "<p>Body</p>", template_id="unknown")
    assert not email_util.send_email(
        "recipient@example.com", "Update", "<p>Body</p>",
        template_id="waitlist_update", unsubscribe_url="https://testserver/waitlist/unsubscribe?token=unused",
    )
    assert not FakeSMTP.messages


def test_confirmation_requires_explicit_second_action_and_is_one_use(mail_app):
    _, client, db_path, _, _ = mail_app
    response = _request(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/waitlist?joined=1"
    assert "Check your email" in client.get(response.headers["location"]).text
    assert len(FakeSMTP.messages) == 1
    assert FakeSMTP.messages[0]["List-Unsubscribe"] is None
    token = _token(FakeSMTP.messages[0])
    assert token not in str(_rows(db_path, "SELECT * FROM waitlist_email_tokens"))
    pending = _rows(db_path, "SELECT * FROM waitlist_signups")[0]
    assert pending["source"] == "footer"
    assert pending["consent_at"] and pending["consent_version"] == "waitlist-updates-v1"
    assert pending["confirmed_at"] is None

    view = client.get("/waitlist/confirm", params={"token": token})
    assert view.status_code == 200
    assert view.headers["Referrer-Policy"] == "no-referrer"
    assert view.headers["Cache-Control"] == "no-store"
    assert _rows(db_path, "SELECT confirmed_at FROM waitlist_signups")[0]["confirmed_at"] is None

    confirmed = client.post("/waitlist/confirm", data={"token": token})
    assert confirmed.status_code == 200
    assert _rows(db_path, "SELECT confirmed_at FROM waitlist_signups")[0]["confirmed_at"]
    assert client.post("/waitlist/confirm", data={"token": token}).status_code == 410
    assert _request(client).status_code == 303
    assert len(FakeSMTP.messages) == 1


def test_expired_and_tampered_confirmation_links_fail_closed(mail_app):
    _, client, db_path, _, _ = mail_app
    assert _request(client).status_code == 303
    token = _token(FakeSMTP.messages[0])
    bad_token = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert client.post("/waitlist/confirm", data={"token": bad_token}).status_code == 410
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE waitlist_email_tokens SET expires_at = '2000-01-01T00:00:00Z'")
    assert client.post("/waitlist/confirm", data={"token": token}).status_code == 410
    assert _rows(db_path, "SELECT confirmed_at FROM waitlist_signups")[0]["confirmed_at"] is None


def test_marketing_requires_verified_sender_address_and_immediate_suppression(mail_app, monkeypatch):
    _, client, db_path, email_util, waitlist = mail_app
    assert _request(client).status_code == 303
    confirm_token = _token(FakeSMTP.messages[0])
    assert client.post("/waitlist/confirm", data={"token": confirm_token}).status_code == 200
    assert not waitlist.send_waitlist_update("recipient@example.com", "Product update", "<p>Update</p>")
    assert len(FakeSMTP.messages) == 1

    monkeypatch.setattr(email_util, "COMPANY_LEGAL_NAME", "Fictional Test Company")
    monkeypatch.setattr(email_util, "COMPANY_POSTAL_ADDRESS", "100 Test Road, Test City")
    assert waitlist.send_waitlist_update("recipient@example.com", "Product update", "<p>Update</p>")
    message = FakeSMTP.messages[-1]
    assert "Fictional Test Company" in message["From"]
    assert message["List-Unsubscribe"].startswith("<https://testserver/waitlist/unsubscribe?token=")
    assert message["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert "100 Test Road, Test City" in message.get_body(preferencelist=("html",)).get_content()
    assert "Unsubscribe" in message.get_body(preferencelist=("plain",)).get_content()
    unsubscribe_token = _token(message)

    assert client.post(
        "/waitlist/unsubscribe", params={"token": unsubscribe_token},
        data={"List-Unsubscribe": "One-Click"},
        headers={"Origin": "https://mail.example.org"},
    ).status_code == 200
    assert client.get("/waitlist/unsubscribe", params={"token": unsubscribe_token}).status_code == 200
    assert _rows(db_path, "SELECT reason FROM email_suppressions")[0]["reason"] == "unsubscribe"
    assert not waitlist.send_waitlist_update("recipient@example.com", "Another update", "<p>Update</p>")
    assert len(FakeSMTP.messages) == 2

    # A new form submission does not clear suppression. Only the new email
    # confirmation can explicitly renew the subscription.
    assert _request(client).status_code == 303
    assert _rows(db_path, "SELECT * FROM email_suppressions")
    new_confirm_token = _token(FakeSMTP.messages[-1])
    assert client.post("/waitlist/confirm", data={"token": new_confirm_token}).status_code == 200
    assert not _rows(db_path, "SELECT * FROM email_suppressions")


def test_smtp_failure_has_no_address_or_token_in_logs_and_can_retry(mail_app, caplog):
    _, client, db_path, _, _ = mail_app
    FakeSMTP.fail = True
    with caplog.at_level("WARNING", logger="safescan.email"):
        failed = _request(client)
    assert failed.status_code == 503
    assert "recipient@example.com" not in caplog.text
    assert "token-should-not-appear" not in caplog.text
    assert len(_rows(db_path, "SELECT token_hash FROM waitlist_email_tokens")) == 1
    assert _rows(db_path, "SELECT last_confirmation_requested_at FROM waitlist_signups")[0]["last_confirmation_requested_at"] is None
    FakeSMTP.fail = False
    assert _request(client).status_code == 303
    assert len(FakeSMTP.messages) == 1
