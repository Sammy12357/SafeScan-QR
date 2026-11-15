"""Account-bound Stripe Checkout and replay-safe subscription webhooks.

No browser redirect, email address, or legacy Payment Link can grant access.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import quote, urlparse

import requests
from fastapi import HTTPException, Request

from db import get_conn
from .audit import iso_from_unix_timestamp, now_iso
from .auth import require_user
from .config import (
    APP_URL, BILLING_LEGAL_ENTITY_NAME, BILLING_POSTAL_ADDRESS,
    BILLING_REFUND_POLICY_TEXT, BILLING_SUPPORT_EMAIL, BILLING_TERMS_VERSION,
    STRIPE_ALPHA_PRICE_ID, STRIPE_ALPHA_PRODUCT_ID,
    STRIPE_BILLING_SETTINGS_CONFIRMED, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
)
from .email_util import email_sending_configured, send_email
from .request_helpers import make_id


PRICE_CENTS = 100
CURRENCY = "usd"
WEBHOOK_TOLERANCE_SECONDS = 300
STRIPE_API = "https://api.stripe.com/v1"
_ID = re.compile(r"^[A-Za-z0-9_]{3,120}$")


def _valid_id(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def require_payment_user(request: Request):
    """Payment authorization hook: wire the shared 18+ account gate here.

    The age-gate branch starts from the same parent commit. Until integrated,
    checkout is additionally fail-closed by owner-controlled billing settings.
    """
    return require_user(request)


def billing_terms_text():
    terms = (
        "US$1 per month, billed monthly until you cancel. Applicable taxes, if "
        "any, are shown by Stripe before payment. Cancel before the next renewal "
        "from Profile → Billing. " + BILLING_REFUND_POLICY_TEXT
    )
    if billing_identity_ready():
        terms += f" Seller: {BILLING_LEGAL_ENTITY_NAME}, {BILLING_POSTAL_ADDRESS}. Billing support: {BILLING_SUPPORT_EMAIL}."
    return terms


def billing_identity_ready():
    return all((
        BILLING_LEGAL_ENTITY_NAME, BILLING_POSTAL_ADDRESS,
        BILLING_SUPPORT_EMAIL, BILLING_REFUND_POLICY_TEXT,
        BILLING_TERMS_VERSION,
    )) and "@" in BILLING_SUPPORT_EMAIL and len(BILLING_REFUND_POLICY_TEXT) <= 500


def stripe_checkout_configured():
    return all((
        STRIPE_SECRET_KEY.startswith(("sk_live_", "sk_test_")),
        STRIPE_ALPHA_PRICE_ID.startswith("price_"),
        STRIPE_ALPHA_PRODUCT_ID.startswith("prod_"),
        STRIPE_WEBHOOK_SECRET.startswith("whsec_"),
        STRIPE_BILLING_SETTINGS_CONFIRMED,
        billing_identity_ready(),
        email_sending_configured(),
    ))


def _stripe_request(method, path, *, data=None, params=None, idempotency_key=None):
    if not STRIPE_SECRET_KEY.startswith(("sk_live_", "sk_test_")):
        raise HTTPException(status_code=503, detail="Card billing is unavailable.")
    headers = {"Authorization": f"Bearer {STRIPE_SECRET_KEY}"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    try:
        response = requests.request(
            method, STRIPE_API + path, headers=headers, data=data, params=params,
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Card billing is temporarily unavailable.") from exc
    if not isinstance(result, dict):
        raise HTTPException(status_code=503, detail="Card billing is temporarily unavailable.")
    return result


def _stripe_price_matches(price):
    product = price.get("product")
    if isinstance(product, dict):
        product = product.get("id")
    recurring = price.get("recurring") or {}
    return (
        price.get("id") == STRIPE_ALPHA_PRICE_ID
        and product == STRIPE_ALPHA_PRODUCT_ID
        and price.get("active") is True
        and price.get("currency") == CURRENCY
        and price.get("unit_amount") == PRICE_CENTS
        and recurring.get("interval") == "month"
        and recurring.get("interval_count") == 1
    )


def _subscription_matches(subscription, intent, customer_id):
    items = ((subscription.get("items") or {}).get("data") or [])
    if len(items) != 1:
        return False
    price = items[0].get("price") or {}
    product = price.get("product")
    if isinstance(product, dict):
        product = product.get("id")
    recurring = price.get("recurring") or {}
    return (
        subscription.get("id") and subscription.get("customer") == customer_id
        and price.get("id") == intent["price_id"]
        and product == intent["product_id"]
        and price.get("currency") == intent["currency"]
        and price.get("unit_amount") == intent["amount_cents"]
        and recurring.get("interval") == "month"
        and recurring.get("interval_count") == 1
        and items[0].get("quantity") == 1
    )


def _period_end(subscription):
    items = ((subscription.get("items") or {}).get("data") or [])
    value = subscription.get("current_period_end") or (items[0].get("current_period_end") if items else None)
    try:
        return iso_from_unix_timestamp(value) if value and int(value) > int(time.time()) else None
    except (TypeError, ValueError):
        return None


def _stripe_redirect_url(result, expected_host):
    url = result.get("url") or ""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != expected_host or parsed.username or parsed.password:
        raise HTTPException(status_code=503, detail="Card billing is temporarily unavailable.")
    return url


def issue_payment_form_token(user, purpose):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat()
    with get_conn() as conn:
        conn.execute("DELETE FROM payment_form_tokens WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
        conn.execute(
            "INSERT INTO payment_form_tokens (token_hash, user_id, session_id, purpose, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token_hash, user["google_id"], user.get("session_id") or user["google_id"], purpose, expires_at),
        )
    return token


def consume_payment_form_token(user, purpose, token):
    if not isinstance(token, str) or not 20 <= len(token) <= 200:
        raise HTTPException(status_code=403, detail="Payment form expired. Reload the page.")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT token_hash FROM payment_form_tokens WHERE token_hash = ? AND user_id = ? AND session_id = ? AND purpose = ? AND expires_at > ?",
            (token_hash, user["google_id"], user.get("session_id") or user["google_id"], purpose, datetime.now(timezone.utc).isoformat()),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="Payment form expired. Reload the page.")
        conn.execute("DELETE FROM payment_form_tokens WHERE token_hash = ?", (token_hash,))


def create_stripe_checkout(user):
    if not stripe_checkout_configured():
        raise HTTPException(status_code=503, detail="Card checkout is unavailable while billing terms and settings are being verified.")
    with get_conn() as conn:
        active = conn.execute(
            """SELECT 1 FROM alpha_subscriptions WHERE user_id = ? AND provider = 'stripe'
               AND status = 'active' AND stripe_verified_at IS NOT NULL
               AND (expires_at IS NULL OR expires_at > ?)""",
            (user["google_id"], now_iso()),
        ).fetchone()
    if active:
        raise HTTPException(status_code=409, detail="You already have a card subscription. Manage it from your profile.")
    price = _stripe_request("GET", "/prices/" + quote(STRIPE_ALPHA_PRICE_ID, safe=""))
    if not _stripe_price_matches(price):
        raise HTTPException(status_code=503, detail="Card checkout is unavailable because the configured price is not US$1 monthly.")
    session = _stripe_request(
        "POST", "/checkout/sessions",
        data={
            "mode": "subscription",
            "payment_method_types[0]": "card",
            "line_items[0][price]": STRIPE_ALPHA_PRICE_ID,
            "line_items[0][quantity]": "1",
            "success_url": APP_URL.rstrip("/") + "/pay/alpha/success",
            "cancel_url": APP_URL.rstrip("/") + "/pay/alpha",
            "client_reference_id": user["google_id"],
            "customer_email": user["email"],
            "consent_collection[terms_of_service]": "required",
            "metadata[safescan_user_id]": user["google_id"],
            "subscription_data[metadata][safescan_user_id]": user["google_id"],
        },
        idempotency_key="safescan-checkout-" + secrets.token_urlsafe(16),
    )
    session_id = session.get("id") or ""
    if not _valid_id(session_id) or not session_id.startswith("cs_"):
        raise HTTPException(status_code=503, detail="Card billing is temporarily unavailable.")
    url = _stripe_redirect_url(session, "checkout.stripe.com")
    accepted_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO stripe_checkout_intents
               (session_id, user_id, email, price_id, product_id, amount_cents,
                currency, consent_version, consent_text, refund_text, accepted_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, user["google_id"], user["email"], STRIPE_ALPHA_PRICE_ID,
             STRIPE_ALPHA_PRODUCT_ID, PRICE_CENTS, CURRENCY,
             BILLING_TERMS_VERSION, billing_terms_text(), BILLING_REFUND_POLICY_TEXT,
             accepted_at, accepted_at),
        )
    return url


def create_stripe_portal(user):
    if not STRIPE_SECRET_KEY.startswith(("sk_live_", "sk_test_")):
        raise HTTPException(status_code=503, detail="Billing management is temporarily unavailable.")
    with get_conn() as conn:
        row = conn.execute(
            """SELECT stripe_customer_id FROM alpha_subscriptions
               WHERE user_id = ? AND provider = 'stripe' AND stripe_verified_at IS NOT NULL
                 AND stripe_customer_id IS NOT NULL""",
            (user["google_id"],),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No card subscription is linked to this account.")
    portal = _stripe_request(
        "POST", "/billing_portal/sessions",
        data={"customer": row["stripe_customer_id"], "return_url": APP_URL.rstrip("/") + "/profile"},
    )
    return _stripe_redirect_url(portal, "billing.stripe.com")


def verify_stripe_webhook_signature(payload: bytes, signature_header: str):
    if not STRIPE_WEBHOOK_SECRET.startswith("whsec_"):
        raise HTTPException(status_code=503, detail="Stripe webhook is unavailable.")
    if len(payload) > 262144:
        raise HTTPException(status_code=413, detail="Stripe webhook payload too large.")
    parts = {}
    for item in (signature_header or "").split(","):
        key, sep, value = item.strip().partition("=")
        if sep:
            parts.setdefault(key, []).append(value)
    try:
        timestamp = int((parts.get("t") or [""])[0])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.") from exc
    if abs(int(time.time()) - timestamp) > WEBHOOK_TOLERANCE_SECONDS:
        raise HTTPException(status_code=400, detail="Expired Stripe signature.")
    signed_payload = str(timestamp).encode() + b"." + payload
    expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, item) for item in parts.get("v1", [])):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.")


def _intent_for_session(conn, session_id):
    return conn.execute("SELECT * FROM stripe_checkout_intents WHERE session_id = ?", (session_id,)).fetchone()


def _current_subscription(conn, subscription_id, customer_id):
    return conn.execute(
        """SELECT s.*, i.price_id, i.product_id, i.amount_cents, i.currency
           FROM alpha_subscriptions s JOIN stripe_checkout_intents i ON i.session_id = s.checkout_session_id
           WHERE s.stripe_subscription_id = ? AND s.stripe_customer_id = ?
             AND s.provider = 'stripe' AND s.stripe_verified_at IS NOT NULL""",
        (subscription_id, customer_id),
    ).fetchone()


def _apply_checkout(conn, session, subscription):
    session_id = session.get("id") or ""
    intent = _intent_for_session(conn, session_id)
    if not intent:
        return {"ignored": "unknown_checkout_session"}
    customer_id = session.get("customer") or ""
    subscription_id = session.get("subscription") or ""
    if not all((
        session.get("object") == "checkout.session",
        session.get("mode") == "subscription",
        session.get("payment_status") == "paid",
        session.get("client_reference_id") == intent["user_id"],
        session.get("amount_subtotal") == intent["amount_cents"],
        isinstance(session.get("amount_total"), int) and session["amount_total"] >= intent["amount_cents"],
        session.get("currency") == intent["currency"],
        _valid_id(customer_id), _valid_id(subscription_id),
    )):
        return {"ignored": "unpaid_or_mismatched_checkout"}
    if subscription is None or subscription.get("id") != subscription_id or not _subscription_matches(subscription, intent, customer_id):
        return {"ignored": "wrong_subscription_product"}
    period_end = _period_end(subscription)
    if subscription.get("status") != "active" or not period_end:
        # A paid Checkout can arrive just before the Subscription is fully
        # available. Return non-2xx so Stripe retries instead of losing it.
        raise HTTPException(status_code=503, detail="Subscription verification is pending.")
    now = now_iso()
    conn.execute(
        """INSERT INTO alpha_subscriptions
           (id, user_id, email, tier, provider, status, purchased_at,
            checkout_session_id, client_reference_id, metadata, stripe_customer_id,
            stripe_subscription_id, current_period_end, expires_at, created_at,
            updated_at, stripe_verified_at)
           VALUES (?, ?, ?, 'alpha_premium', 'stripe', 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_id, tier, provider) DO UPDATE SET
             email = excluded.email, status = 'active', purchased_at = excluded.purchased_at,
             checkout_session_id = excluded.checkout_session_id,
             client_reference_id = excluded.client_reference_id,
             metadata = excluded.metadata, stripe_customer_id = excluded.stripe_customer_id,
             stripe_subscription_id = excluded.stripe_subscription_id,
             current_period_end = excluded.current_period_end, expires_at = excluded.expires_at,
             canceled_at = NULL, cancel_at_period_end = 0,
             updated_at = excluded.updated_at, stripe_verified_at = excluded.stripe_verified_at""",
        (make_id("sub"), intent["user_id"], intent["email"], now, session_id,
         intent["user_id"], json.dumps({"source": "stripe_verified_webhook"}),
         customer_id, subscription_id, period_end, period_end, now, now, now),
    )
    conn.execute("UPDATE stripe_checkout_intents SET status = 'paid' WHERE session_id = ?", (session_id,))
    return {"activated": True, "session_id": session_id}


def _apply_subscription_update(conn, event_type, obj, subscription):
    subscription_id = obj.get("id") if event_type.startswith("customer.subscription") else obj.get("subscription")
    customer_id = obj.get("customer")
    if not subscription_id or not customer_id:
        return {"ignored": "missing_subscription_identity"}
    current = _current_subscription(conn, subscription_id, customer_id)
    if not current:
        return {"ignored": "unlinked_subscription"}
    if event_type == "customer.subscription.deleted":
        conn.execute(
            """UPDATE alpha_subscriptions SET status = 'canceled', canceled_at = ?, expires_at = ?,
               updated_at = ? WHERE id = ?""",
            (now_iso(), now_iso(), now_iso(), current["id"]),
        )
        return {"canceled": True}
    if subscription is None or not _subscription_matches(subscription, current, customer_id):
        conn.execute(
            "UPDATE alpha_subscriptions SET status = 'inactive', updated_at = ? WHERE id = ?",
            (now_iso(), current["id"]),
        )
        return {"ignored": "wrong_subscription_product"}
    period_end = _period_end(subscription)
    status = "active" if subscription.get("status") == "active" and period_end else "inactive"
    conn.execute(
        """UPDATE alpha_subscriptions SET status = ?, current_period_end = ?,
           expires_at = ?, cancel_at_period_end = ?, updated_at = ? WHERE id = ?""",
        (status, period_end, period_end,
         1 if subscription.get("cancel_at_period_end") else 0, now_iso(), current["id"]),
    )
    return {"status": status}


def process_stripe_webhook_event(event):
    if not isinstance(event, dict) or not isinstance(event.get("data"), dict):
        raise HTTPException(status_code=400, detail="Invalid Stripe event.")
    event_id = event.get("id") or ""
    event_type = event.get("type") or ""
    obj = (event["data"].get("object") or {})
    if not _valid_id(event_id) or not isinstance(event_type, str) or not isinstance(obj, dict):
        raise HTTPException(status_code=400, detail="Invalid Stripe event.")
    if event.get("livemode") is not (STRIPE_SECRET_KEY.startswith("sk_live_")):
        return {"ignored": "wrong_stripe_mode"}
    supported = {
        "checkout.session.completed", "customer.subscription.updated",
        "customer.subscription.deleted", "invoice.paid",
    }
    if event_type not in supported:
        return {"ignored": True}
    with get_conn() as conn:
        existing = conn.execute("SELECT 1 FROM stripe_webhook_events WHERE event_id = ?", (event_id,)).fetchone()
        if existing:
            return {"duplicate": True, "session_id": obj.get("id") if event_type == "checkout.session.completed" else None}
        if event_type == "checkout.session.completed" and not _intent_for_session(conn, obj.get("id") or ""):
            # A genuine Stripe session can belong to another product/account.
            # Never fetch or attach it without a locally created checkout.
            return {"ignored": "unknown_checkout_session"}

    subscription = None
    if event_type == "checkout.session.completed":
        subscription_id = obj.get("subscription") or ""
        if obj.get("payment_status") == "paid" and _valid_id(subscription_id):
            subscription = _stripe_request("GET", "/subscriptions/" + quote(subscription_id, safe=""))
    elif event_type == "customer.subscription.updated":
        subscription = obj
    elif event_type == "invoice.paid":
        subscription_id = obj.get("subscription") or ""
        if _valid_id(subscription_id):
            subscription = _stripe_request("GET", "/subscriptions/" + quote(subscription_id, safe=""))

    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM stripe_webhook_events WHERE event_id = ?", (event_id,)).fetchone():
            return {"duplicate": True, "session_id": obj.get("id") if event_type == "checkout.session.completed" else None}
        if event_type == "checkout.session.completed":
            result = _apply_checkout(conn, obj, subscription)
        else:
            result = _apply_subscription_update(conn, event_type, obj, subscription)
        conn.execute(
            "INSERT INTO stripe_webhook_events (event_id, event_type, processed_at) VALUES (?, ?, ?)",
            (event_id, event_type, now_iso()),
        )
    return result


def send_confirmation_if_pending(session_id):
    if not session_id:
        return False
    with get_conn() as conn:
        row = conn.execute(
            """SELECT email, consent_text, consent_version, receipt_sent_at
               FROM stripe_checkout_intents WHERE session_id = ? AND status = 'paid'""",
            (session_id,),
        ).fetchone()
    if not row or row["receipt_sent_at"]:
        return False
    manage_url = APP_URL.rstrip("/") + "/profile"
    body = (
        f"Your SafeScan Alpha subscription is active.\n\n{row['consent_text']}\n\n"
        f"Manage or cancel: {manage_url}\n"
        f"Terms version: {row['consent_version']}\n"
        f"Seller: {BILLING_LEGAL_ENTITY_NAME}, {BILLING_POSTAL_ADDRESS}\n"
        f"Support: {BILLING_SUPPORT_EMAIL}\n"
    )
    if not send_email(row["email"], "SafeScan Alpha subscription confirmation", "<p>" + escape(body).replace("\n", "<br>") + "</p>", body):
        raise HTTPException(status_code=503, detail="Subscription confirmation email is temporarily unavailable.")
    with get_conn() as conn:
        conn.execute("UPDATE stripe_checkout_intents SET receipt_sent_at = ? WHERE session_id = ? AND receipt_sent_at IS NULL", (now_iso(), session_id))
    return True
