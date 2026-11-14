"""Regression tests for verified and idempotent Alpha payment activation."""

import hashlib
import hmac
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from test_auth_persistence import auth_app, db_rows, register


def signed_event(client, event, *, timestamp=None):
    payload = json.dumps(event, separators=(",", ":"))
    timestamp = int(time.time()) if timestamp is None else timestamp
    sig = hmac.new(b"whsec_test_secret", f"{timestamp}.{payload}".encode(), hashlib.sha256).hexdigest()
    return client.post("/webhooks/stripe", content=payload, headers={"stripe-signature": f"t={timestamp},v1={sig}"})


def checkout_event(user_id, *, event_id="evt_paid", session_id="cs_paid", payment_status="paid", email="buyer@example.com"):
    return {
        "id": event_id,
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": session_id,
            "object": "checkout.session",
            "customer": "cus_paid",
            "subscription": "sub_paid",
            "client_reference_id": user_id,
            "customer_details": {"email": email},
            "payment_status": payment_status,
            "payment_link": "plink_alpha_test",
            "mode": "subscription",
            "amount_total": 100,
            "currency": "usd",
        }},
    }


def user_id_for(db_path, email="buyer@example.com"):
    return db_rows(db_path, "SELECT google_id FROM users WHERE email = ?", (email,))[0]["google_id"]


def checkout_reference_for(client, db_path, email="buyer@example.com"):
    assert client.get("/pay/alpha").status_code == 200
    return db_rows(
        db_path,
        "SELECT reference FROM alpha_checkout_references WHERE user_id = ?",
        (user_id_for(db_path, email),),
    )[0]["reference"]


def test_success_page_never_activates_without_webhook(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    assert client.get("/pay/alpha/success").status_code == 200
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions") == []


def test_guest_cannot_start_unattributable_stripe_checkout(auth_app):
    _, _, db_path = auth_app
    # The payment link's client_reference_id is created only for a signed-in
    # account; a guest checkout would require manual attribution by email.
    guest = TestClient(__import__("hackabull").qr_app, base_url="https://testserver")
    page = guest.get("/pay/alpha")
    assert page.status_code == 200
    assert "Sign in to pay by card" in page.text
    assert "https://buy.stripe.com" not in page.text
    assert "solana:" not in page.text


def test_stripe_checkout_reference_handles_legacy_auth0_subject(auth_app, monkeypatch):
    module, client, db_path = auth_app
    legacy_id = "google-oauth2|legacy-sub"
    with __import__("sqlite3").connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (google_id, email, role, status) VALUES (?, ?, 'user', 'active')",
            (legacy_id, "legacy@example.com"),
        )
    monkeypatch.setattr(
        module.payments_stripe, "get_session_user",
        lambda request: {"google_id": legacy_id, "email": "legacy@example.com"},
    )

    checkout_url = module.payments_stripe.alpha_stripe_checkout_url(None)
    checkout_reference = parse_qs(urlsplit(checkout_url).query)["client_reference_id"][0]
    assert re.fullmatch(r"[A-Za-z0-9_-]+", checkout_reference)
    assert checkout_reference != legacy_id
    event = checkout_event(checkout_reference)
    assert signed_event(client, event).status_code == 200
    assert db_rows(db_path, "SELECT user_id FROM alpha_subscriptions") == [{"user_id": legacy_id}]


def test_checkout_reference_cannot_relink_a_second_session(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    reference = checkout_reference_for(client, db_path)
    assert signed_event(client, checkout_event(reference)).status_code == 200
    other = checkout_event(reference, event_id="evt_second", session_id="cs_second")
    other["data"]["object"]["subscription"] = "sub_second"

    assert signed_event(client, other).status_code == 200
    assert db_rows(db_path, "SELECT stripe_subscription_id FROM alpha_subscriptions") == [
        {"stripe_subscription_id": "sub_paid"}
    ]
    assert db_rows(db_path, "SELECT outcome FROM stripe_events WHERE event_id = 'evt_second'") == [
        {"outcome": "unmatched"}
    ]


def test_legacy_unverified_checkout_cannot_gain_access_from_new_invoice(auth_app):
    module, client, db_path = auth_app
    register(client, "buyer@example.com")
    user_id = user_id_for(db_path)
    with __import__("sqlite3").connect(db_path) as conn:
        conn.execute(
            """INSERT INTO alpha_subscriptions
               (id, user_id, email, tier, provider, status, purchased_at,
                checkout_session_id, stripe_subscription_id, metadata, created_at, updated_at)
               VALUES ('legacy', ?, 'buyer@example.com', 'alpha_premium', 'stripe',
                       'active', '2026-01-01', 'cs_other_product', 'sub_other_product',
                       ?, '2026-01-01', '2026-01-01')""",
            (user_id, json.dumps({"source": "stripe_webhook"})),
        )
    invoice = {"id": "evt_legacy_invoice", "type": "invoice.paid", "data": {"object": {
        "id": "in_legacy", "object": "invoice", "subscription": "sub_other_product",
        "status": "paid", "amount_paid": 100,
        "current_period_end": int(time.time()) + 86400,
    }}}

    assert signed_event(client, invoice).status_code == 200
    assert module.payments_stripe.has_active_alpha(user_id) is False
    assert db_rows(db_path, "SELECT outcome FROM stripe_events WHERE event_id = 'evt_legacy_invoice'") == [
        {"outcome": "unmatched"}
    ]


@pytest.mark.parametrize("payment_status", [None, "unpaid", "no_payment_required"])
def test_checkout_requires_paid_status(auth_app, payment_status):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    event = checkout_event(checkout_reference_for(client, db_path), payment_status=payment_status)
    assert signed_event(client, event).status_code == 200
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions WHERE status = 'active'") == []


@pytest.mark.parametrize("client_reference_id", [None, "not-a-user"])
def test_stripe_email_cannot_choose_an_account(auth_app, client_reference_id):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    event = checkout_event(client_reference_id)
    assert signed_event(client, event).status_code == 200
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions") == []


@pytest.mark.parametrize("field,value", [
    ("payment_link", "plink_other_product"),
    ("payment_link", None),
    ("mode", "payment"),
    ("amount_total", 0),
    ("subscription", None),
])
def test_other_paid_checkout_cannot_activate_alpha(auth_app, field, value):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    event = checkout_event(checkout_reference_for(client, db_path))
    event["data"]["object"][field] = value
    assert signed_event(client, event).status_code == 200
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions") == []


def test_missing_payment_link_configuration_retries_without_consuming_event(auth_app, monkeypatch):
    module, client, db_path = auth_app
    register(client, "buyer@example.com")
    monkeypatch.setattr(module.payments_stripe, "ALPHA_STRIPE_PAYMENT_LINK_ID", "")
    event = checkout_event(checkout_reference_for(client, db_path))
    assert signed_event(client, event).status_code == 503
    assert db_rows(db_path, "SELECT event_id FROM stripe_events") == []


def test_known_payment_link_can_settle_in_local_currency(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    event = checkout_event(checkout_reference_for(client, db_path))
    event["data"]["object"]["currency"] = "eur"
    assert signed_event(client, event).status_code == 200
    assert db_rows(db_path, "SELECT status FROM alpha_subscriptions") == [{"status": "active"}]


def test_stripe_replay_by_event_id_or_object_and_type_is_idempotent(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    event = checkout_event(checkout_reference_for(client, db_path))
    assert signed_event(client, event).status_code == 200
    assert signed_event(client, event).status_code == 200
    duplicate_event = checkout_event(checkout_reference_for(client, db_path), event_id="evt_same_object")
    assert signed_event(client, duplicate_event).status_code == 200
    assert db_rows(db_path, "SELECT event_id FROM stripe_events") == [{"event_id": "evt_paid"}]
    assert len(db_rows(db_path, "SELECT id FROM alpha_subscriptions")) == 1


def test_async_checkout_only_activates_after_payment_succeeds(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    user_id = user_id_for(db_path)
    reference = checkout_reference_for(client, db_path)
    pending = checkout_event(reference, event_id="evt_pending", payment_status="unpaid")
    assert signed_event(client, pending).status_code == 200
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions") == []
    paid = checkout_event(reference, event_id="evt_async", payment_status="paid")
    paid["type"] = "checkout.session.async_payment_succeeded"
    assert signed_event(client, paid).status_code == 200
    assert db_rows(db_path, "SELECT status FROM alpha_subscriptions") == [{"status": "active"}]


def test_unrelated_customer_invoice_does_not_extend_alpha(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    assert signed_event(client, checkout_event(checkout_reference_for(client, db_path))).status_code == 200
    unrelated = {"id": "evt_unrelated_invoice", "type": "invoice.paid", "data": {"object": {
        "id": "in_unrelated", "object": "invoice", "customer": "cus_paid",
        "subscription": "sub_different", "status": "paid", "amount_paid": 100, "currency": "usd",
        "current_period_end": int(time.time()) + 86400,
    }}}
    assert signed_event(client, unrelated).status_code == 200
    assert db_rows(db_path, "SELECT current_period_end FROM alpha_subscriptions") == [{"current_period_end": None}]


def test_repeatable_subscription_updates_are_not_deduplicated_by_object(auth_app):
    module, client, db_path = auth_app
    register(client, "buyer@example.com")
    user_id = user_id_for(db_path)
    assert signed_event(client, checkout_event(checkout_reference_for(client, db_path))).status_code == 200
    subscription = {"id": "evt_sub_1", "type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_paid", "object": "subscription", "customer": "cus_paid",
        "status": "past_due", "current_period_end": int(time.time()) + 86400,
    }}}
    assert signed_event(client, subscription).status_code == 200
    assert module.payments_stripe.has_active_alpha(user_id) is False
    subscription["id"] = "evt_sub_2"
    subscription["data"]["object"]["status"] = "active"
    assert signed_event(client, subscription).status_code == 200
    assert db_rows(db_path, "SELECT status FROM alpha_subscriptions") == [{"status": "active"}]
    assert module.payments_stripe.has_active_alpha(user_id) is False
    invoice = {"id": "evt_invoice_paid", "type": "invoice.paid", "data": {"object": {
        "id": "in_alpha", "object": "invoice", "subscription": "sub_paid",
        "status": "paid", "amount_paid": 100, "currency": "usd",
        "current_period_end": int(time.time()) + 86400,
    }}}
    assert signed_event(client, invoice).status_code == 200
    assert module.payments_stripe.has_active_alpha(user_id) is True


def test_unpaid_subscription_update_does_not_extend_paid_access(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    assert signed_event(client, checkout_event(checkout_reference_for(client, db_path))).status_code == 200
    invoice = {"id": "evt_first_invoice", "type": "invoice.paid", "data": {"object": {
        "id": "in_first", "object": "invoice", "subscription": "sub_paid",
        "status": "paid", "amount_paid": 100, "currency": "usd",
        "current_period_end": int(time.time()) + 86400,
    }}}
    assert signed_event(client, invoice).status_code == 200
    before = db_rows(db_path, "SELECT expires_at FROM alpha_subscriptions")[0]["expires_at"]
    update = {"id": "evt_future_period", "type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_paid", "object": "subscription", "status": "active",
        "current_period_end": int(time.time()) + 30 * 86400,
    }}}
    assert signed_event(client, update).status_code == 200
    assert db_rows(db_path, "SELECT expires_at FROM alpha_subscriptions") == [{"expires_at": before}]


def test_terminal_stripe_cancellation_cannot_be_reversed_by_old_event(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    assert signed_event(client, checkout_event(checkout_reference_for(client, db_path))).status_code == 200
    deleted = {"id": "evt_terminal", "type": "customer.subscription.deleted", "data": {"object": {
        "id": "sub_paid", "object": "subscription", "customer": "cus_paid", "status": "canceled",
    }}}
    assert signed_event(client, deleted).status_code == 200
    late_update = {"id": "evt_late_update", "type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_paid", "object": "subscription", "customer": "cus_paid", "status": "active",
        "current_period_end": int(time.time()) + 86400,
    }}}
    assert signed_event(client, late_update).status_code == 200
    assert db_rows(db_path, "SELECT status FROM alpha_subscriptions") == [{"status": "canceled"}]


def test_modern_paid_invoice_line_establishes_access_period(auth_app):
    module, client, db_path = auth_app
    register(client, "buyer@example.com")
    user_id = user_id_for(db_path)
    assert signed_event(client, checkout_event(checkout_reference_for(client, db_path))).status_code == 200
    period_end = int(time.time()) + 86400
    invoice = {"id": "evt_modern_invoice", "type": "invoice.paid", "data": {"object": {
        "id": "in_modern", "object": "invoice", "status": "paid",
        "amount_paid": 100, "currency": "usd",
        "lines": {"data": [{
            "parent": {"type": "subscription_item_details", "subscription_item_details": {"subscription": "sub_paid"}},
            "period": {"end": period_end},
        }]},
    }}}
    assert signed_event(client, invoice).status_code == 200
    assert module.payments_stripe.has_active_alpha(user_id) is True


def test_zero_amount_invoice_does_not_extend_access(auth_app):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    assert signed_event(client, checkout_event(checkout_reference_for(client, db_path))).status_code == 200
    invoice = {"id": "evt_free_invoice", "type": "invoice.paid", "data": {"object": {
        "id": "in_free", "object": "invoice", "subscription": "sub_paid",
        "status": "paid", "amount_paid": 0, "currency": "usd",
        "current_period_end": int(time.time()) + 86400,
    }}}
    assert signed_event(client, invoice).status_code == 200
    assert db_rows(db_path, "SELECT expires_at FROM alpha_subscriptions") == [{"expires_at": None}]


@pytest.mark.parametrize("offset", [-601, 601])
def test_stripe_rejects_signed_payload_outside_five_minute_window(auth_app, offset):
    _, client, db_path = auth_app
    register(client, "buyer@example.com")
    event = checkout_event(checkout_reference_for(client, db_path))
    assert signed_event(client, event, timestamp=int(time.time()) + offset).status_code == 400
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions") == []


def test_solana_uses_finalized_commitment_for_both_rpc_calls(auth_app):
    module, client, db_path = auth_app
    register(client, "buyer@example.com")
    response = client.get("/pay/alpha")
    reference = re.search(r"reference=([1-9A-HJ-NP-Za-km-z]{32,44})", response.text).group(1)
    recipient = module.ALPHA_SOLANA_RECIPIENT
    calls = []

    def fake_rpc(method, params):
        calls.append((method, params))
        if method == "getSignaturesForAddress":
            return [{"signature": "finalized_sig", "err": None, "confirmationStatus": "finalized"}]
        return {"transaction": {"message": {"accountKeys": [reference, recipient]}},
                "meta": {"preBalances": [0, 0], "postBalances": [0, 10_000_000]}}

    module.payments_solana.solana_rpc = fake_rpc
    assert module.payments_solana.verify_alpha_solana_payment(reference) == "finalized_sig"
    assert calls[0][1][1]["commitment"] == "finalized"
    assert calls[1][1][1]["commitment"] == "finalized"


def test_solana_signature_cannot_activate_two_accounts(auth_app):
    module, first_client, db_path = auth_app
    register(first_client, "buyer@example.com")
    first_reference = re.search(r"reference=([1-9A-HJ-NP-Za-km-z]{32,44})", first_client.get("/pay/alpha").text).group(1)
    first_user = {"google_id": user_id_for(db_path), "email": "buyer@example.com"}
    module.payments_solana.record_alpha_solana_subscription(first_user, first_reference, "same_chain_signature")

    second_client = TestClient(module.qr_app, base_url="https://testserver")
    register(second_client, "second@example.com")
    second_reference = re.search(r"reference=([1-9A-HJ-NP-Za-km-z]{32,44})", second_client.get("/pay/alpha").text).group(1)
    second_user = {"google_id": user_id_for(db_path, "second@example.com"), "email": "second@example.com"}
    with pytest.raises(module.SafeScanError):
        module.payments_solana.record_alpha_solana_subscription(second_user, second_reference, "same_chain_signature")
    assert db_rows(db_path, "SELECT id FROM alpha_subscriptions WHERE user_id = ?", (second_user["google_id"],)) == []
