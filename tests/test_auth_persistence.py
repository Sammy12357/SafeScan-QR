import importlib
import hashlib
import hmac
from html import unescape
import io
import json
import re
from pathlib import Path
import sqlite3
import sys
import time

import pytest
import qrcode
from fastapi.testclient import TestClient


def set_everywhere(name, value):
    """Bind ``name`` to ``value`` on every loaded ``hackabull`` submodule.

    The backend is now a package, so a helper imported ``from .x import foo``
    has its own binding inside each consumer module. Overriding it only on the
    top-level package would miss those copies, so mirror the old single-module
    behaviour by setting the name wherever it appears. (Each test re-imports the
    package fresh, so these direct assignments do not leak across tests.)
    """
    for mod_name, mod in list(sys.modules.items()):
        if (mod_name == "hackabull" or mod_name.startswith("hackabull.")) and hasattr(mod, name):
            setattr(mod, name, value)


@pytest.fixture()
def auth_app(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_secret")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_secret")
    monkeypatch.setenv("STRIPE_ALPHA_PRICE_ID", "price_alpha")
    monkeypatch.setenv("STRIPE_ALPHA_PRODUCT_ID", "prod_alpha")
    monkeypatch.setenv("STRIPE_BILLING_SETTINGS_CONFIRMED", "true")
    monkeypatch.setenv("BILLING_LEGAL_ENTITY_NAME", "Example Corporation")
    monkeypatch.setenv("BILLING_POSTAL_ADDRESS", "123 Test Street")
    monkeypatch.setenv("BILLING_SUPPORT_EMAIL", "support@example.com")
    monkeypatch.setenv("ALPHA_SOLANA_RECIPIENT", "11111111111111111111111111111111")
    monkeypatch.setenv("ALPHA_SOLANA_AMOUNT_SOL", "0.01")
    monkeypatch.setenv("ALPHA_SOLANA_PRICE_USD", "1.00")
    monkeypatch.setenv("SOLANA_USD_PRICE_URL", "")
    monkeypatch.setenv("SOLANA_USD_PRICE_FALLBACK", "100")
    monkeypatch.setenv("ALPHA_SOLANA_ACCESS_DAYS", "30")

    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    module = importlib.import_module("hackabull")
    monkeypatch.setattr(importlib.import_module("hackabull.routes_scan_auth"), "LOCAL_AUTH_ENABLED", True)
    module.RATE_LIMITS.clear()
    set_everywhere("run_fraud_checks", lambda *args, **kwargs: [])
    set_everywhere("email_sending_configured", lambda: True)
    set_everywhere("send_email", lambda *args, **kwargs: True)

    yield module, TestClient(module.qr_app, base_url="https://testserver"), db_path

    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]


def db_rows(db_path, query, params=()):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def session_count(db_path):
    return db_rows(db_path, "SELECT COUNT(*) AS total FROM sessions WHERE revoked_at IS NULL")[0]["total"]


def register(client, email="person@example.com", password="password123"):
    return client.post("/auth/register", data={"email": email, "password": password})


def login(client, email="person@example.com", password="password123"):
    return client.post("/auth/login", data={"email": email, "password": password})


def stripe_signature(payload, secret="whsec_test_secret"):
    timestamp = str(int(time.time()))
    signature = hmac.new(secret.encode("utf-8"), f"{timestamp}.{payload}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={signature}"


def test_email_registration_persists_user_credentials_and_session(auth_app):
    module, client, db_path = auth_app

    response = register(client, "Person@Example.com")

    assert response.status_code == 200
    assert module.SESSION_COOKIE_NAME in client.cookies
    users = db_rows(db_path, "SELECT google_id, email, google_sub FROM users WHERE lower(email) = ?", ("person@example.com",))
    credentials = db_rows(db_path, "SELECT email, user_id, password_hash FROM local_credentials WHERE email = ?", ("person@example.com",))
    sessions = db_rows(db_path, "SELECT google_id FROM sessions WHERE revoked_at IS NULL")
    assert len(users) == 1
    assert users[0]["email"] == "person@example.com"
    assert users[0]["google_sub"] is None
    assert len(credentials) == 1
    assert credentials[0]["user_id"] == users[0]["google_id"]
    assert credentials[0]["password_hash"] != "password123"
    assert len(sessions) == 1
    assert sessions[0]["google_id"] == users[0]["google_id"]


def stripe_subscription(*, price_id="price_alpha", status="active"):
    return {
        "id": "sub_123", "customer": "cus_123", "status": status,
        "current_period_end": int(time.time()) + 30 * 86400,
        "items": {"data": [{
            "quantity": 1,
            "price": {
                "id": price_id, "product": "prod_alpha", "currency": "usd",
                "unit_amount": 100, "recurring": {"interval": "month", "interval_count": 1},
            },
        }]},
    }


def fake_stripe_api(*, wrong_product=False):
    def request(method, path, **kwargs):
        if path == "/prices/price_alpha":
            return {**stripe_subscription()["items"]["data"][0]["price"], "active": True}
        if path == "/checkout/sessions":
            assert kwargs["data"]["line_items[0][price]"] == "price_alpha"
            return {"id": "cs_test_123", "url": "https://checkout.stripe.com/c/pay/test123"}
        if path == "/subscriptions/sub_123":
            return stripe_subscription(price_id="price_other" if wrong_product else "price_alpha")
        if path == "/billing_portal/sessions":
            assert kwargs["data"]["customer"] == "cus_123"
            return {"url": "https://billing.stripe.com/p/session/test123"}
        raise AssertionError(path)
    return request


def stripe_checkout_event(user_id, *, event_id="evt_checkout", payment_status="paid", amount_total=100):
    return {
        "id": event_id, "type": "checkout.session.completed", "livemode": False,
        "data": {"object": {
            "id": "cs_test_123", "object": "checkout.session", "mode": "subscription",
            "customer": "cus_123", "subscription": "sub_123",
            "customer_email": "different@example.com", "client_reference_id": user_id,
            "payment_status": payment_status, "amount_subtotal": 100,
            "amount_total": amount_total,
            "currency": "usd",
        }},
    }


def post_stripe_event(client, event, signature=None):
    payload = json.dumps(event, separators=(",", ":"))
    return client.post("/webhooks/stripe", content=payload, headers={"stripe-signature": signature or stripe_signature(payload)})


def payment_token(page, action):
    form = re.search(r"<form action=['\"]" + re.escape(action) + r"['\"](.*?)</form>", page, re.S)
    assert form, action
    return re.search(r"name=['\"]payment_token['\"] value=['\"]([^'\"]+)", form.group(1)).group(1)


def start_card_checkout(client, user_email):
    page = client.get("/pay/alpha")
    assert page.status_code == 200
    assert "US$1 per month" in page.text
    assert "not refunded after a billing period starts" in page.text
    assert "type='checkbox' name='recurring_consent' value='yes' required" in page.text
    token = payment_token(page.text, "/pay/alpha/stripe/checkout")
    missing_consent = client.post("/pay/alpha/stripe/checkout", data={"payment_token": token}, follow_redirects=False)
    assert missing_consent.status_code == 400
    page = client.get("/pay/alpha")
    token = payment_token(page.text, "/pay/alpha/stripe/checkout")
    checkout = client.post(
        "/pay/alpha/stripe/checkout",
        data={"payment_token": token, "recurring_consent": "yes"},
        follow_redirects=False,
    )
    assert checkout.status_code == 303
    assert checkout.headers["location"].startswith("https://checkout.stripe.com/")


def test_success_page_and_unlinked_webhook_cannot_activate_access(auth_app):
    _, client, db_path = auth_app
    register(client, "alpha@example.com")
    user_id = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("alpha@example.com",))[0]["google_id"]
    success = client.get("/pay/alpha/success")
    assert success.status_code == 200
    assert "does not activate access" in success.text
    assert not db_rows(db_path, "SELECT * FROM alpha_subscriptions")
    forged = post_stripe_event(client, stripe_checkout_event(user_id))
    assert forged.status_code == 200
    assert forged.json()["result"]["ignored"] == "unknown_checkout_session"
    assert not db_rows(db_path, "SELECT * FROM alpha_subscriptions")


def test_stripe_checkout_webhook_receipt_portal_and_cancel(auth_app):
    _, client, db_path = auth_app
    register(client, "stripe@example.com")
    user_id = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("stripe@example.com",))[0]["google_id"]
    importlib.import_module("hackabull.payments_stripe")._stripe_request = fake_stripe_api()
    sent = []
    set_everywhere("send_email", lambda *args, **kwargs: sent.append(args) or True)
    start_card_checkout(client, "stripe@example.com")
    intent = db_rows(db_path, "SELECT user_id, consent_version, consent_text, status FROM stripe_checkout_intents")[0]
    assert intent["user_id"] == user_id
    assert intent["consent_version"] == "2026-11-alpha-v1"
    assert "Cancel before the next renewal" in intent["consent_text"]
    assert intent["status"] == "pending"
    event = stripe_checkout_event(user_id)
    assert post_stripe_event(client, event).status_code == 200
    assert post_stripe_event(client, event).json()["result"]["duplicate"] is True
    rows = db_rows(db_path, "SELECT status, stripe_customer_id, stripe_subscription_id, stripe_verified_at FROM alpha_subscriptions")
    assert len(rows) == 1
    assert rows[0]["status"] == "active"
    assert rows[0]["stripe_customer_id"] == "cus_123"
    assert rows[0]["stripe_subscription_id"] == "sub_123"
    assert rows[0]["stripe_verified_at"]
    assert db_rows(db_path, "SELECT receipt_sent_at FROM stripe_checkout_intents")[0]["receipt_sent_at"]
    assert len(sent) == 1
    assert "Manage or cancel:" in sent[0][3]
    portal = client.get("/pay/alpha/manage", follow_redirects=False)
    assert portal.status_code == 303
    assert portal.headers["location"].startswith("https://billing.stripe.com/")
    canceled = post_stripe_event(client, {
        "id": "evt_deleted", "type": "customer.subscription.deleted", "livemode": False,
        "data": {"object": {"id": "sub_123", "customer": "cus_123", "status": "canceled"}},
    })
    assert canceled.status_code == 200
    assert db_rows(db_path, "SELECT status FROM alpha_subscriptions")[0]["status"] == "canceled"


def test_stripe_rejects_bad_signatures_unpaid_and_wrong_product(auth_app):
    _, client, db_path = auth_app
    register(client, "stripe@example.com")
    user_id = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("stripe@example.com",))[0]["google_id"]
    stripe_module = importlib.import_module("hackabull.payments_stripe")
    stripe_module._stripe_request = fake_stripe_api()
    start_card_checkout(client, "stripe@example.com")
    event = stripe_checkout_event(user_id)
    assert post_stripe_event(client, event, signature="t=123,v1=bad").status_code == 400
    assert post_stripe_event(client, event, signature=stripe_signature(json.dumps(event), secret="whsec_wrong")).status_code == 400
    assert post_stripe_event(client, stripe_checkout_event(user_id, event_id="evt_unpaid", payment_status="unpaid")).json()["result"]["ignored"] == "unpaid_or_mismatched_checkout"
    assert post_stripe_event(client, stripe_checkout_event("another_account", event_id="evt_wrong_user")).json()["result"]["ignored"] == "unpaid_or_mismatched_checkout"
    stripe_module._stripe_request = fake_stripe_api(wrong_product=True)
    assert post_stripe_event(client, stripe_checkout_event(user_id, event_id="evt_wrong_product")).json()["result"]["ignored"] == "wrong_subscription_product"
    assert not db_rows(db_path, "SELECT * FROM alpha_subscriptions WHERE provider = 'stripe'")


def test_card_checkout_requires_verified_business_and_stripe_settings(auth_app):
    _, client, db_path = auth_app
    register(client, "stripe@example.com")
    set_everywhere("STRIPE_BILLING_SETTINGS_CONFIRMED", False)
    page = client.get("/pay/alpha")
    assert page.status_code == 200
    assert "action='/pay/alpha/stripe/checkout'" not in page.text
    assert "buy.stripe.com" not in page.text
    assert not db_rows(db_path, "SELECT * FROM stripe_checkout_intents")


def test_billing_record_blocks_automatic_account_erasure(auth_app):
    _, client, db_path = auth_app
    register(client, "stripe@example.com")
    importlib.import_module("hackabull.payments_stripe")._stripe_request = fake_stripe_api()
    start_card_checkout(client, "stripe@example.com")
    export = importlib.import_module("hackabull.legal").get_user_export(
        "stripe@example.com",
        db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("stripe@example.com",))[0]["google_id"],
    )
    assert len(export["billingConsents"]) == 1
    request = client.post("/legal/data-request", data={"email": "stripe@example.com", "request_type": "erasure"})
    assert request.status_code == 200
    assert "billing-record review" in request.text
    assert db_rows(db_path, "SELECT email FROM users WHERE email = ?", ("stripe@example.com",))


def test_solana_payment_link_and_verification_store_subscription(auth_app):
    module, client, db_path = auth_app
    register(client, "solana@example.com")

    payment = client.get("/pay/alpha")

    assert payment.status_code == 200
    assert "Pay with Solana" in payment.text
    assert "one-time payment for 30 days" in payment.text
    assert "reference=" in payment.text
    reference = re.search(r"reference=([1-9A-HJ-NP-Za-km-z]{32,44})", payment.text).group(1)
    rows = db_rows(
        db_path,
        "SELECT email, status, reference, amount_usd, sol_usd_price, amount_sol, amount_lamports FROM alpha_solana_payment_references WHERE email = ?",
        ("solana@example.com",),
    )
    assert rows == [{
        "email": "solana@example.com",
        "status": "pending",
        "reference": reference,
        "amount_usd": "1",
        "sol_usd_price": "100",
        "amount_sol": "0.01",
        "amount_lamports": 10000000,
    }]

    set_everywhere("verify_alpha_solana_payment", lambda ref: "")
    pending = client.post("/pay/alpha/solana/verify", data={"payment_token": payment_token(payment.text, "/pay/alpha/solana/verify")})
    assert pending.status_code == 202
    assert not db_rows(db_path, "SELECT * FROM alpha_subscriptions WHERE email = ? AND provider = 'solana'", ("solana@example.com",))

    set_everywhere("verify_alpha_solana_payment", lambda ref: "solana_signature_123")
    payment = client.get("/pay/alpha")
    verified = client.post("/pay/alpha/solana/verify", data={"payment_token": payment_token(payment.text, "/pay/alpha/solana/verify")})

    assert verified.status_code == 200
    assert "Solana payment verified" in verified.text
    subscriptions = db_rows(
        db_path,
        "SELECT email, provider, status, client_reference_id, expires_at FROM alpha_subscriptions WHERE email = ? AND provider = 'solana'",
        ("solana@example.com",),
    )
    assert len(subscriptions) == 1
    assert subscriptions[0]["provider"] == "solana"
    assert subscriptions[0]["status"] == "active"
    assert subscriptions[0]["client_reference_id"] == reference
    assert subscriptions[0]["expires_at"].endswith("Z")

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE alpha_subscriptions SET expires_at = '2000-01-01T00:00:00Z' WHERE email = ? AND provider = 'solana'",
            ("solana@example.com",),
        )
    client.get("/pay/alpha")
    expired = db_rows(db_path, "SELECT status FROM alpha_subscriptions WHERE email = ? AND provider = 'solana'", ("solana@example.com",))
    assert expired[0]["status"] == "expired"


def test_email_login_creates_session_and_profile_uses_db_user(auth_app):
    _, setup_client, db_path = auth_app
    register(setup_client)

    login_client = TestClient(sys.modules["hackabull"].qr_app, base_url="https://testserver")
    response = login(login_client)
    profile = login_client.get("/api/user/profile")

    assert response.status_code == 200
    assert profile.status_code == 200
    assert profile.json()["email"] == "person@example.com"
    assert session_count(db_path) == 2
    assert len(db_rows(db_path, "SELECT * FROM users WHERE lower(email) = ?", ("person@example.com",))) == 1


def test_remembered_device_restores_session_when_short_cookie_is_missing(auth_app):
    module, setup_client, db_path = auth_app
    register(setup_client, "remember@example.com")
    remember_token = setup_client.cookies.get(module.REMEMBER_ME_COOKIE_NAME)
    assert remember_token

    returning_client = TestClient(module.qr_app, base_url="https://testserver")
    returning_client.cookies.set(module.REMEMBER_ME_COOKIE_NAME, remember_token)

    profile = returning_client.get("/api/user/profile")

    assert profile.status_code == 200
    assert profile.json()["email"] == "remember@example.com"
    assert module.SESSION_COOKIE_NAME in returning_client.cookies
    remember_values = [cookie.value for cookie in returning_client.cookies.jar if cookie.name == module.REMEMBER_ME_COOKIE_NAME]
    assert any(value != remember_token for value in remember_values)
    persistent_sessions = db_rows(
        db_path,
        "SELECT revoked_at FROM persistent_sessions ORDER BY created_at",
    )
    assert len(persistent_sessions) == 2
    assert persistent_sessions[0]["revoked_at"] is not None
    assert persistent_sessions[1]["revoked_at"] is None


def test_remembered_device_renders_homepage_as_signed_in_after_reopen(auth_app):
    module, setup_client, _ = auth_app
    register(setup_client, "reopen@example.com")
    remember_token = setup_client.cookies.get(module.REMEMBER_ME_COOKIE_NAME)
    assert remember_token

    returning_client = TestClient(module.qr_app, base_url="https://testserver")
    returning_client.cookies.set(module.REMEMBER_ME_COOKIE_NAME, remember_token)

    response = returning_client.get("/")

    assert response.status_code == 200
    assert "reopen@example.com" in response.text
    assert "Sign out" in response.text
    assert "Sign in / Sign up" not in response.text
    assert module.SESSION_COOKIE_NAME in returning_client.cookies
    remember_values = [cookie.value for cookie in returning_client.cookies.jar if cookie.name == module.REMEMBER_ME_COOKIE_NAME]
    assert any(value != remember_token for value in remember_values)


def test_invalid_credentials_do_not_create_session(auth_app):
    _, setup_client, db_path = auth_app
    register(setup_client)
    before = session_count(db_path)

    response = login(TestClient(sys.modules["hackabull"].qr_app, base_url="https://testserver"), password="wrong-password")

    assert response.status_code == 401
    assert "Email or password is incorrect." in response.text
    assert 'data-server-error-focus' in response.text
    assert '/static/server-error-focus.js?v=form-error-focus-v1' in response.text
    assert session_count(db_path) == before


def test_local_auth_form_keeps_email_and_return_path_but_not_password(auth_app):
    _, client, _ = auth_app
    response = client.post("/auth/register", data={
        "email": "person@example.com", "password": "secret", "next": "/profile",
    })
    assert response.status_code == 400
    assert 'value="person@example.com"' in response.text
    assert 'name="next" value="/profile"' in response.text
    assert "Use a longer password" in response.text
    assert 'aria-describedby="reg-password-error"' in response.text
    assert 'value="secret"' not in response.text


def test_google_login_persists_provider_user_and_session(auth_app, monkeypatch):
    module, client, db_path = auth_app

    monkeypatch.setattr(
        module.id_token,
        "verify_oauth2_token",
        lambda credential, request, client_id: {
            "sub": "google-sub-1",
            "email": "google@example.com",
            "name": "Google User",
            "picture": "https://example.com/avatar.png",
        },
    )
    response = client.post("/auth/google", data={"credential": "valid-token"})

    assert response.status_code == 200
    assert module.SESSION_COOKIE_NAME in client.cookies
    users = db_rows(db_path, "SELECT google_id, email, google_sub FROM users WHERE lower(email) = ?", ("google@example.com",))
    sessions = db_rows(db_path, "SELECT google_id FROM sessions WHERE revoked_at IS NULL")
    assert len(users) == 1
    assert users[0]["google_sub"] == "google-sub-1"
    assert len(sessions) == 1
    assert sessions[0]["google_id"] == users[0]["google_id"]


def test_google_then_local_registration_blocks_duplicate_email(auth_app, monkeypatch):
    module, client, db_path = auth_app
    monkeypatch.setattr(
        module.id_token,
        "verify_oauth2_token",
        lambda credential, request, client_id: {
            "sub": "google-sub-2",
            "email": "shared@example.com",
        },
    )

    google_response = client.post("/auth/google", data={"credential": "valid-token"})
    local_response = register(TestClient(module.qr_app, base_url="https://testserver"), "shared@example.com")

    assert google_response.status_code == 200
    assert local_response.status_code == 409
    assert "already linked to an account" in local_response.text
    users = db_rows(db_path, "SELECT google_id, email, google_sub FROM users WHERE lower(email) = ?", ("shared@example.com",))
    credentials = db_rows(db_path, "SELECT user_id FROM local_credentials WHERE email = ?", ("shared@example.com",))
    assert len(users) == 1
    assert users[0]["google_sub"] == "google-sub-2"
    assert credentials == []


def test_mobile_sign_in_then_local_registration_blocks_duplicate_email(auth_app, monkeypatch):
    module, client, db_path = auth_app
    monkeypatch.setattr(
        module.id_token,
        "verify_oauth2_token",
        lambda credential, request, client_id: {
            "sub": "mobile-sub-1",
            "email": "mobile-shared@example.com",
            "name": "Mobile User",
        },
    )

    verify_response = client.post("/auth/verify", json={"token": "valid-token"})
    local_response = register(TestClient(module.qr_app, base_url="https://testserver"), "mobile-shared@example.com")

    assert verify_response.status_code == 200
    assert local_response.status_code == 409
    assert "already linked to an account" in local_response.text
    users = db_rows(db_path, "SELECT google_id, email, google_sub FROM users WHERE lower(email) = ?", ("mobile-shared@example.com",))
    credentials = db_rows(db_path, "SELECT user_id FROM local_credentials WHERE email = ?", ("mobile-shared@example.com",))
    assert len(users) == 1
    assert users[0]["google_sub"] == "mobile-sub-1"
    assert credentials == []


def test_local_registration_blocks_existing_email(auth_app):
    _, client, db_path = auth_app

    first = register(client, "Repeat@Example.com")
    second = register(TestClient(sys.modules["hackabull"].qr_app, base_url="https://testserver"), "repeat@example.com")

    assert first.status_code == 200
    assert second.status_code == 409
    assert "already linked to an account" in second.text
    assert len(db_rows(db_path, "SELECT * FROM users WHERE lower(email) = ?", ("repeat@example.com",))) == 1
    assert len(db_rows(db_path, "SELECT * FROM local_credentials WHERE lower(email) = ?", ("repeat@example.com",))) == 1


def test_signed_in_user_cannot_create_another_account(auth_app):
    _, client, db_path = auth_app

    first = register(client, "signed-in@example.com")
    second = register(client, "second-account@example.com")

    assert first.status_code == 200
    assert second.status_code == 409
    assert "already signed in" in second.text
    assert len(db_rows(db_path, "SELECT * FROM users WHERE lower(email) = ?", ("second-account@example.com",))) == 0
    assert len(db_rows(db_path, "SELECT * FROM local_credentials WHERE lower(email) = ?", ("second-account@example.com",))) == 0


def test_user_scan_history_saves_and_fetches_by_user_id(auth_app):
    module, client, db_path = auth_app
    register(client, "scanner@example.com")
    user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("scanner@example.com",))[0]
    analysis = {
        "score": 47,
        "status": "CAUTION",
        "reasons": [{"label": "Redirect Chain", "severity": "low"}],
    }

    scan_id = module.save_user_scan(user["google_id"], "https://example.com/path", analysis, email="scanner@example.com")
    history = module.get_user_scan_history(user["google_id"])

    assert scan_id.startswith("scan_")
    assert len(history) == 1
    assert history[0]["user_id"] == user["google_id"]
    assert history[0]["email"] == "scanner@example.com"
    assert history[0]["url"] == "https://example.com/path"
    assert history[0]["risk_score"] == 47
    assert history[0]["threat_type"] == "CAUTION"


def test_history_api_returns_only_current_users_scans(auth_app):
    module, client, db_path = auth_app
    register(client, "first@example.com")
    first_user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("first@example.com",))[0]
    module.save_user_scan(first_user["google_id"], "https://first.example", {"score": 12, "status": "SAFE"}, email="first@example.com")

    other_client = TestClient(module.qr_app, base_url="https://testserver")
    register(other_client, "second@example.com")
    second_user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("second@example.com",))[0]
    module.save_user_scan(second_user["google_id"], "https://second.example", {"score": 88, "status": "DANGEROUS"}, email="second@example.com")

    response = other_client.get("/api/history")

    assert response.status_code == 200
    rows = response.json()
    assert [row["url"] for row in rows] == ["https://second.example"]


def test_duplicate_qr_scans_do_not_increment_user_counter(auth_app):
    module, client, db_path = auth_app
    register(client, "dupe@example.com")
    user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("dupe@example.com",))[0]

    first_counted = module.record_unique_scan(
        "dupe@example.com",
        "https://same.example/qr",
        "",
        user_id=user["google_id"],
    )
    second_counted = module.record_unique_scan(
        "dupe@example.com",
        "https://same.example/qr",
        "",
        user_id=user["google_id"],
    )

    assert first_counted is True
    assert second_counted is False
    assert module.get_scan_count("dupe@example.com") == 1
    assert len(db_rows(db_path, "SELECT * FROM scan_events WHERE email = ?", ("dupe@example.com",))) == 1


def test_login_redirects_missing_username_to_onboarding(auth_app):
    module, client, db_path = auth_app

    response = client.post("/auth/register", data={"email": "name-me@example.com", "password": "password123"}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/onboarding/username"
    users = db_rows(db_path, "SELECT username FROM users WHERE email = ?", ("name-me@example.com",))
    assert users[0]["username"] is None


def test_username_onboarding_saves_unique_username(auth_app):
    module, client, db_path = auth_app
    client.post("/auth/register", data={"email": "named@example.com", "password": "password123"})

    response = client.post("/onboarding/username", data={"username": "SafeScanner_1"}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    users = db_rows(db_path, "SELECT username FROM users WHERE email = ?", ("named@example.com",))
    assert users[0]["username"] == "SafeScanner_1"


def test_username_form_keeps_invalid_entry_and_discord_context(auth_app):
    _, client, _ = auth_app
    register(client, "username-error@example.com")
    response = client.post("/profile/username", data={"username": "bad name"})
    assert response.status_code == 400
    assert 'value="bad name"' in response.text
    assert 'aria-invalid="true"' in response.text
    assert 'data-server-error-focus' in response.text
    assert '/static/server-error-focus.js?v=form-error-focus-v1' in response.text
    assert "Use 3 to 24 letters" in response.text


def test_profile_redirect_notice_uses_allowlisted_copy(auth_app, monkeypatch):
    _, client, _ = auth_app
    register(client, "notice@example.com")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(routes, "discord_linking_configured", lambda: True)
    response = client.get("/profile?discord_error=discord_expired")
    assert response.status_code == 200
    assert "Discord linking expired" in response.text
    assert 'class="profile-notice" role="alert"' in response.text
    forged = client.get("/profile?discord_error=forged-secret-message")
    assert "forged-secret-message" not in forged.text


def test_solana_verification_hides_provider_detail(auth_app, monkeypatch, caplog):
    module, client, _ = auth_app
    register(client, "payment-error@example.com")
    from hackabull.audit import SafeScanError
    routes = importlib.import_module("hackabull.routes_pages")
    monkeypatch.setattr(routes, "get_or_create_alpha_solana_reference", lambda _user: {"reference": "test-reference"})

    def failed_verification(_reference):
        raise SafeScanError("Solana RPC error: private upstream token", 502, code="payment_network_unavailable")

    monkeypatch.setattr(routes, "verify_alpha_solana_payment", failed_verification)
    payment = client.get("/pay/alpha")
    with caplog.at_level("ERROR", logger="safescan.errors"):
        response = client.post("/pay/alpha/solana/verify", data={"payment_token": payment_token(payment.text, "/pay/alpha/solana/verify")})
    assert response.status_code == 502
    assert "We couldn't reach the Solana network" in unescape(response.text)
    assert "private upstream token" not in response.text
    assert response.headers["X-Request-ID"] in caplog.text
    assert "private upstream token" not in caplog.text
    record = next(json.loads(item.getMessage()) for item in caplog.records if item.name == "safescan.errors")
    assert record["route"] == "/pay/alpha/solana/verify"
    assert record["status_code"] == 502
    assert record["code"] == "payment_network_unavailable"


def test_solana_network_failure_uses_public_error_code(auth_app, monkeypatch):
    payments = importlib.import_module("hackabull.payments_solana")
    from hackabull.audit import SafeScanError

    def unavailable(*_args, **_kwargs):
        raise payments.requests.ConnectionError("private upstream host")

    monkeypatch.setattr(payments.requests, "post", unavailable)
    with pytest.raises(SafeScanError) as caught:
        payments.solana_rpc("getSignaturesForAddress", [])
    assert caught.value.status_code == 502
    assert caught.value.code == "payment_network_unavailable"


def test_global_leaderboard_groups_by_username_and_scan_count(auth_app):
    module, client, db_path = auth_app
    register(client, "leader@example.com")
    leader_user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("leader@example.com",))[0]
    module.set_user_username(leader_user["google_id"], "LeaderOne")
    module.record_unique_scan("leader@example.com", "https://one.example", "", user_id=leader_user["google_id"])
    module.record_unique_scan("leader@example.com", "https://two.example", "", user_id=leader_user["google_id"])

    other_client = TestClient(module.qr_app, base_url="https://testserver")
    register(other_client, "runner@example.com")
    runner_user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("runner@example.com",))[0]
    module.set_user_username(runner_user["google_id"], "RunnerUp")
    module.record_unique_scan("runner@example.com", "https://one.example", "", user_id=runner_user["google_id"])

    leaders = module.get_global_leaderboard()

    assert [row["username"] for row in leaders[:2]] == ["LeaderOne", "RunnerUp"]
    assert [row["scan_count"] for row in leaders[:2]] == [2, 1]


def test_global_leaderboard_recovers_count_from_saved_history(auth_app):
    module, client, db_path = auth_app
    register(client, "history-leader@example.com")
    user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("history-leader@example.com",))[0]
    module.set_user_username(user["google_id"], "HistoryLeader")
    module.save_user_scan(user["google_id"], "https://one.example", {"score": 10, "status": "SAFE"}, email="history-leader@example.com")
    module.save_user_scan(user["google_id"], "https://two.example", {"score": 10, "status": "SAFE"}, email="history-leader@example.com")

    leaders = module.get_global_leaderboard()

    assert leaders[0]["username"] == "HistoryLeader"
    assert leaders[0]["scan_count"] == 2
    assert leaders[0]["total_saved_scans"] == 2


def test_global_leaderboard_counts_every_saved_history_scan(auth_app):
    module, client, db_path = auth_app
    register(client, "repeat-scanner@example.com")
    user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("repeat-scanner@example.com",))[0]
    module.set_user_username(user["google_id"], "RepeatScanner")

    for url in [
        "https://one.example",
        "https://one.example",
        "https://two.example",
        "https://two.example",
        "https://two.example",
    ]:
        module.save_user_scan(user["google_id"], url, {"score": 10, "status": "SAFE"}, email="repeat-scanner@example.com")

    leaders = module.get_global_leaderboard()

    assert leaders[0]["username"] == "RepeatScanner"
    assert leaders[0]["scan_count"] == 5
    assert leaders[0]["total_saved_scans"] == 5


def test_global_leaderboard_excludes_registered_users_with_zero_scans(auth_app):
    module, client, db_path = auth_app
    register(client, "scanner-no-name@example.com")
    scanner = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("scanner-no-name@example.com",))[0]
    module.record_unique_scan("scanner-no-name@example.com", "https://scan.example", "", user_id=scanner["google_id"])

    other_client = TestClient(module.qr_app, base_url="https://testserver")
    register(other_client, "zero@example.com")
    zero_user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("zero@example.com",))[0]

    leaders = module.get_global_leaderboard()
    by_user_id = {row["user_id"]: row for row in leaders}

    assert scanner["google_id"] in by_user_id
    assert zero_user["google_id"] not in by_user_id
    assert by_user_id[scanner["google_id"]]["scan_count"] == 1
    assert by_user_id[scanner["google_id"]]["public_name"] == "sc***@example.com"


def test_malicious_qr_database_is_public_and_filters_scans(auth_app):
    _, client, db_path = auth_app
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("safe", "safe@example.com", "https://safe.example", 10, "SAFE", "{}", 0, "2026-06-01T00:00:00Z", "safe-user"),
                ("mal-old", "a@example.com", "https://evil.example/login", 84, "HIGH", "{}", 0, "2026-06-02T00:00:00Z", "user-a"),
                ("mal-new", "b@example.com", "https://evil.example/login", 91, "MALICIOUS", "{}", 0, "2026-06-03T00:00:00Z", "user-b"),
                ("verdict-only", "c@example.com", "https://phish.example/wallet", 20, "MALICIOUS", "{}", 0, "2026-06-04T00:00:00Z", "user-c"),
            ],
        )
        conn.executemany(
            "INSERT INTO url_blocklist (id, url, reason, added_by, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                ("confirmed-old", "https://evil.com/login", "Admin confirmed", "admin@example.com", "2026-06-02T00:00:00Z"),
                ("confirmed-new", "https://evil.com/reset?token=PRIVATE", "Admin confirmed", "admin@example.com", "2026-06-03T00:00:00Z"),
                ("confirmed-other", "https://phish.com/wallet", "Admin confirmed", "admin@example.com", "2026-06-04T00:00:00Z"),
            ],
        )

    page = client.get("/malicious-database")
    response = client.get("/api/malicious-qr")

    assert page.status_code == 200
    assert "Malicious QR Database" in page.text
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["total"] == 2
    assert [entry["domain"] for entry in data["entries"]] == ["phish.com", "evil.com"]
    evil = data["entries"][1]
    assert evil["reports"] == 2
    assert evil["lastReportedAt"] == "2026-06-03T00:00:00Z"
    assert data["stats"]["totalDomains"] == 2
    assert data["stats"]["totalReports"] == 3
    assert "PRIVATE" not in response.text
    assert "login" not in response.text
    assert "wallet" not in response.text


def test_malicious_qr_database_search_pagination_and_compat_endpoint(auth_app):
    _, client, db_path = auth_app
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO url_blocklist (id, url, reason, added_by, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("one", "https://first-bad.com", "Admin confirmed", "admin@example.com", "2026-06-01T00:00:00Z"),
                ("two", "https://second-bad.com", "Admin confirmed", "admin@example.com", "2026-06-02T00:00:00Z"),
                ("three", "https://needle-bad.com", "Admin confirmed", "admin@example.com", "2026-06-03T00:00:00Z"),
            ],
        )

    first_page = client.get("/api/malicious-qr?limit=2&page=1").json()
    second_page = client.get("/api/malicious-qr?limit=2&page=2").json()
    searched = client.get("/api/qr-codes?malicious=true&q=needle").json()
    unsupported = client.get("/api/qr-codes")

    assert first_page["total"] == 3
    assert first_page["totalPages"] == 2
    assert [entry["domain"] for entry in first_page["entries"]] == ["needle-bad.com", "second-bad.com"]
    assert [entry["domain"] for entry in second_page["entries"]] == ["first-bad.com"]
    assert searched["total"] == 1
    assert searched["entries"][0]["domain"] == "needle-bad.com"
    assert searched["stats"]["totalDomains"] == 3
    assert unsupported.status_code == 400


def test_public_threat_feed_does_not_expose_scan_urls_or_regenerate_qrs(auth_app):
    _, client, db_path = auth_app
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("safe", "safe@example.com", "https://safe.example", 10, "SAFE", "{}", 0, "2026-06-01T00:00:00Z", "safe-user"),
                ("bad", "bad@example.com", "https://unreviewed.com/reset?token=PRIVATE_SCAN_TOKEN#fragment", 95, "MALICIOUS", "{}", 0, "2026-06-02T00:00:00Z", "bad-user"),
                ("local", "bad@example.com", "http://127.0.0.1/reset?token=LOCAL_SCAN_TOKEN", 95, "MALICIOUS", "{}", 0, "2026-06-02T00:00:00Z", "bad-user"),
            ],
        )
        conn.execute(
            "INSERT INTO url_blocklist (id, url, reason, added_by, created_at) VALUES (?, ?, ?, ?, ?)",
            ("curated", "https://user:password@bad.com/secret?token=CURATED_TOKEN#fragment", "Admin confirmed", "admin@example.com", "2026-06-02T00:00:00Z"),
        )

    feed = client.get("/api/malicious-qr")
    compat = client.get("/api/qr-codes?malicious=true")
    search = client.get("/api/malicious-qr", params={"q": "PRIVATE_SCAN_TOKEN"})
    curated_search = client.get("/api/malicious-qr", params={"q": "CURATED_TOKEN"})
    image = client.get("/api/malicious-qr/image", params={"u": "https://unreviewed.com/reset?token=PRIVATE_SCAN_TOKEN#fragment"})

    for response in (feed, compat):
        assert response.status_code == 200
        assert response.json()["entries"][0]["domain"] == "bad.com"
        assert response.json()["total"] == 1
        assert not any(token in response.text for token in ("PRIVATE_SCAN_TOKEN", "LOCAL_SCAN_TOKEN", "CURATED_TOKEN", "user:password", "reset", "fragment"))
        assert "unreviewed.com" not in response.text
    assert search.json()["total"] == 0
    assert curated_search.json()["total"] == 0
    assert image.status_code == 410
    assert image.headers["content-type"].startswith("application/json")
    assert image.headers["cache-control"] == "no-store"


def test_public_threat_feed_never_labels_parent_of_confirmed_subdomain(auth_app):
    _, client, db_path = auth_app
    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO url_blocklist (id, url, reason, added_by, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                ("site", "https://foo.squarespace.com/steal", "Admin confirmed", "admin@example.com", "2026-06-01T00:00:00Z"),
                ("docs", "https://docs.google.com/steal", "Admin confirmed", "admin@example.com", "2026-06-02T00:00:00Z"),
                ("blog", "https://foo.medium.com/steal", "Admin confirmed", "admin@example.com", "2026-06-03T00:00:00Z"),
                ("subdomain", "https://bad.customer.com/steal", "Admin confirmed", "admin@example.com", "2026-06-04T00:00:00Z"),
                ("root", "https://confirmed.com/steal", "Admin confirmed", "admin@example.com", "2026-06-05T00:00:00Z"),
            ],
        )

    response = client.get("/api/malicious-qr")
    assert response.status_code == 200
    assert [entry["domain"] for entry in response.json()["entries"]] == ["confirmed.com"]
    assert response.json()["total"] == 1
    assert response.json()["stats"]["totalReports"] == 1


def test_time_only_formatter_removes_iso_date(auth_app):
    module, _, _ = auth_app

    assert module.format_time_only("2026-05-12T04:52:11.952379Z") == "04:52:11"
    assert module.format_time_only("2026-05-12T23:59:59Z") == "23:59:59"


def test_uploaded_qr_image_decodes_saves_history_and_increments_counter(auth_app):
    module, client, db_path = auth_app
    register(client, "upload@example.com")
    user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("upload@example.com",))[0]
    module.set_user_username(user["google_id"], "UploadUser")
    qr_image = qrcode.make("https://example.com/uploaded-qr")
    buffer = io.BytesIO()
    qr_image.save(buffer, format="PNG")
    buffer.seek(0)

    response = client.post(
        "/search_qr_api",
        data={"user_email": "upload@example.com", "wallet_address": "", "device_fingerprint": ""},
        files={"file": ("scan.png", buffer, "image/png")},
    )

    assert response.status_code == 200
    assert "https://example.com/uploaded-qr" in response.text
    assert module.get_scan_count("upload@example.com") == 1
    history = db_rows(db_path, "SELECT user_id, url FROM scan_history WHERE email = ?", ("upload@example.com",))
    assert history[-1]["user_id"] == user["google_id"]
    assert history[-1]["url"] == "https://example.com/uploaded-qr"


def test_uploaded_aztec_style_code_decodes_with_zxing_fallback(auth_app):
    fixture = Path(r"C:\Users\Restr\Downloads\Screenshot 2026-05-07 224158.png")
    if not fixture.exists():
        pytest.skip("Local Aztec-code screenshot fixture is not available.")
    module, client, db_path = auth_app
    register(client, "aztec@example.com")
    user = db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", ("aztec@example.com",))[0]
    module.set_user_username(user["google_id"], "AztecUser")

    with fixture.open("rb") as uploaded:
        response = client.post(
            "/search_qr_api",
            data={"user_email": "aztec@example.com", "wallet_address": "", "device_fingerprint": ""},
            files={"file": ("aztec.png", uploaded, "image/png")},
        )

    assert response.status_code == 200
    assert "No QR code or valid URL detected" not in response.text
    assert module.get_scan_count("aztec@example.com") == 1
    history = db_rows(db_path, "SELECT user_id, url FROM scan_history WHERE email = ?", ("aztec@example.com",))
    assert history[-1]["user_id"] == user["google_id"]
    assert history[-1]["url"]
