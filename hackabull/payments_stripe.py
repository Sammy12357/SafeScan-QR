from __future__ import annotations
import requests
import json
import warnings
import io
import sqlite3
import hashlib
import hmac
import math
import re
import asyncio
import base64
import ipaddress
import secrets
import socket
import time
import csv
from decimal import Decimal, InvalidOperation
from html import escape as escape_html
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import os
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from db import (
    assert_owns_row,
    clear_rls_context,
    database_path,
    database_storage_status,
    get_conn,
    rls_user_id,
    set_rls_context,
    user_scoped_select,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .audit import iso_from_unix_timestamp
from .audit import now_iso
from .auth import get_session_user
from .config import ALPHA_STRIPE_PAYMENT_LINK
from .config import ALPHA_STRIPE_PAYMENT_LINK_ID
from .config import STRIPE_WEBHOOK_SECRET
from .request_helpers import make_id
import logging

_log = logging.getLogger(__name__)
STRIPE_WEBHOOK_TOLERANCE_SECONDS = 300

# =============================================================================
# STRIPE SUBSCRIPTION PAYMENTS & WEBHOOKS
# =============================================================================
def alpha_stripe_checkout_url(request: Request):
    if not ALPHA_STRIPE_PAYMENT_LINK:
        return ""

    user = get_session_user(request)
    if not user:
        return ""
    params = []
    if user.get("email"):
        params.append(("prefilled_email", user["email"]))
    if user.get("google_id"):
        params.append(("client_reference_id", user["google_id"]))

    if not user.get("google_id"):
        return ""

    separator = "&" if "?" in ALPHA_STRIPE_PAYMENT_LINK else "?"
    return f"{ALPHA_STRIPE_PAYMENT_LINK}{separator}{urlencode(params)}"

def verify_stripe_webhook_signature(payload: bytes, signature_header: str):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Stripe webhook secret is not configured.")
    parts = {}
    for item in (signature_header or "").split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts.setdefault(key.strip(), []).append(value.strip())
    timestamp = (parts.get("t") or [""])[0]
    signatures = parts.get("v1") or []
    if not timestamp or not signatures or len(parts.get("t", [])) != 1:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature header.")
    try:
        signed_at = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature timestamp.") from exc
    if abs(time.time() - signed_at) > STRIPE_WEBHOOK_TOLERANCE_SECONDS:
        raise HTTPException(status_code=400, detail="Stripe signature timestamp is outside the allowed window.")
    try:
        signed_payload = timestamp.encode("utf-8") + b"." + payload
        expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.") from exc
    if not any(hmac.compare_digest(expected, signature) for signature in signatures):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.")

def stripe_user_identity(conn, client_reference_id):
    """Resolve a signed checkout reference to an existing user, never by email."""
    if not isinstance(client_reference_id, str) or not client_reference_id:
        return None
    return conn.execute(
        "SELECT google_id, email FROM users WHERE google_id = ? AND status = 'active'",
        (client_reference_id,),
    ).fetchone()


def stripe_invoice_subscription_and_period(obj):
    """Read both legacy and current Stripe invoice subscription line shapes."""
    subscription_id = obj.get("subscription")
    lines = obj.get("lines") or {}
    entries = (lines.get("data") or []) if isinstance(lines, dict) else []
    matching_periods = []
    seen_subscription_ids = set()
    for line in entries:
        if not isinstance(line, dict):
            continue
        parent = line.get("parent") or {}
        details = (parent.get("subscription_item_details") or {}) if isinstance(parent, dict) else {}
        if not isinstance(details, dict):
            details = {}
        line_subscription = details.get("subscription") or line.get("subscription")
        if not isinstance(line_subscription, str) or not line_subscription:
            continue
        seen_subscription_ids.add(line_subscription)
        period = line.get("period") or {}
        end = period.get("end") if isinstance(period, dict) else None
        if isinstance(end, int) and not isinstance(end, bool):
            matching_periods.append((line_subscription, end))
    if not subscription_id and len(seen_subscription_ids) == 1:
        subscription_id = next(iter(seen_subscription_ids))
    if not isinstance(subscription_id, str) or not subscription_id:
        return None, None
    end = max((end for line_id, end in matching_periods if line_id == subscription_id), default=None)
    return subscription_id, end


def upsert_alpha_subscription_from_stripe(conn, obj, event_type):
    metadata = obj.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    client_reference_id = obj.get("client_reference_id") or metadata.get("client_reference_id")
    stripe_customer_id = obj.get("customer")
    if event_type == "invoice.paid":
        stripe_subscription_id, invoice_period_end = stripe_invoice_subscription_and_period(obj)
        amount_paid = obj.get("amount_paid")
        if (
            obj.get("status") != "paid"
            or not isinstance(amount_paid, int) or isinstance(amount_paid, bool) or amount_paid <= 0
            or not stripe_subscription_id
        ):
            return {"ignored": True, "reason": "invoice_not_paid_for_alpha"}
    else:
        invoice_period_end = None
        stripe_subscription_id = obj.get("subscription") or (
            obj.get("id") if event_type.startswith("customer.subscription.") else None
        )
    if event_type != "customer.subscription.deleted" and isinstance(stripe_subscription_id, str):
        # Deletion is terminal for this subscription ID. Late checkout, invoice,
        # and update deliveries must not reactivate it.
        deleted = conn.execute(
            """SELECT 1 FROM stripe_events
               WHERE event_type = 'customer.subscription.deleted' AND object_id = ?
               LIMIT 1""",
            (stripe_subscription_id,),
        ).fetchone()
        if deleted:
            return {"ignored": True, "reason": "subscription_deleted"}
    if event_type.startswith("checkout.session."):
        if obj.get("payment_status") != "paid":
            return {"ignored": True, "reason": "payment_not_paid"}
        amount = obj.get("amount_total")
        if (
            not ALPHA_STRIPE_PAYMENT_LINK_ID
            or obj.get("payment_link") != ALPHA_STRIPE_PAYMENT_LINK_ID
            or obj.get("mode") != "subscription"
            or not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0
            or not isinstance(stripe_subscription_id, str) or not stripe_subscription_id
        ):
            return {"ignored": True, "reason": "not_alpha_checkout"}
        identity = stripe_user_identity(conn, client_reference_id)
    else:
        # Later lifecycle events can only update a checkout already attached to
        # a user. Invoice metadata and customer email never establish identity.
        identity = None
        if isinstance(stripe_subscription_id, str) and stripe_subscription_id:
            identity = conn.execute(
                """SELECT u.google_id, u.email FROM alpha_subscriptions AS a
                   JOIN users AS u ON u.google_id = a.user_id AND u.status = 'active'
                   WHERE a.provider = 'stripe' AND a.checkout_session_id IS NOT NULL
                     AND a.stripe_subscription_id = ?
                   LIMIT 1""",
                (stripe_subscription_id,),
            ).fetchone()
    if identity is None:
        return {"unmatched": True, "type": event_type}
    user_id, stored_email = identity["google_id"], identity["email"]
    event_status = obj.get("status") or "active"
    cancel_at_period_end = 1 if obj.get("cancel_at_period_end") else 0
    current_period_start = iso_from_unix_timestamp(obj.get("current_period_start"))
    current_period_end = iso_from_unix_timestamp(invoice_period_end or obj.get("current_period_end"))
    canceled_at = iso_from_unix_timestamp(obj.get("canceled_at"))
    purchased_at = iso_from_unix_timestamp(obj.get("created")) or now_iso()

    if event_type in {"checkout.session.completed", "checkout.session.async_payment_succeeded"}:
        event_status = "active"
    elif event_type == "invoice.paid":
        event_status = "active"
    elif event_type == "customer.subscription.deleted":
        event_status = "canceled"
        canceled_at = canceled_at or now_iso()
    elif event_type == "customer.subscription.updated" and event_status == "canceled":
        canceled_at = canceled_at or now_iso()

    # Only a verified paid event can extend the entitlement. Subscription
    # lifecycle updates may report a future period before its invoice is paid.
    expires_at = canceled_at if event_status == "canceled" else (
        current_period_end if event_type in {
            "checkout.session.completed", "checkout.session.async_payment_succeeded", "invoice.paid"
        } else None
    )
    updated_at = now_iso()
    webhook_metadata = {
        "source": "stripe_webhook",
        "eventType": event_type,
        "stripeObjectId": obj.get("id"),
        "rawStatus": obj.get("status"),
    }

    conn.execute(
        """
            INSERT INTO alpha_subscriptions
                (id, user_id, email, tier, provider, status, purchased_at,
                 checkout_session_id, stripe_payment_link, client_reference_id, metadata,
                 stripe_customer_id, stripe_subscription_id, current_period_start,
                 current_period_end, cancel_at_period_end, canceled_at, expires_at,
                 created_at, updated_at)
            VALUES (?, ?, ?, 'alpha_premium', 'stripe', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, tier, provider) DO UPDATE SET
                email = excluded.email,
                status = excluded.status,
                checkout_session_id = COALESCE(excluded.checkout_session_id, alpha_subscriptions.checkout_session_id),
                stripe_payment_link = excluded.stripe_payment_link,
                client_reference_id = COALESCE(excluded.client_reference_id, alpha_subscriptions.client_reference_id),
                metadata = excluded.metadata,
                stripe_customer_id = COALESCE(excluded.stripe_customer_id, alpha_subscriptions.stripe_customer_id),
                stripe_subscription_id = COALESCE(excluded.stripe_subscription_id, alpha_subscriptions.stripe_subscription_id),
                current_period_start = COALESCE(excluded.current_period_start, alpha_subscriptions.current_period_start),
                current_period_end = COALESCE(excluded.current_period_end, alpha_subscriptions.current_period_end),
                cancel_at_period_end = excluded.cancel_at_period_end,
                canceled_at = COALESCE(excluded.canceled_at, alpha_subscriptions.canceled_at),
                expires_at = COALESCE(excluded.expires_at, alpha_subscriptions.expires_at),
                updated_at = excluded.updated_at
            """,
        (
            make_id("sub"),
            user_id,
            stored_email,
            event_status,
            purchased_at,
            obj.get("id") if obj.get("object") == "checkout.session" else None,
            ALPHA_STRIPE_PAYMENT_LINK,
            client_reference_id or user_id,
            json.dumps(webhook_metadata),
            stripe_customer_id,
            stripe_subscription_id,
            current_period_start,
            current_period_end,
            cancel_at_period_end,
            canceled_at,
            expires_at,
            updated_at,
            updated_at,
        ),
    )
    return {"email": stored_email, "status": event_status, "stripeSubscriptionId": stripe_subscription_id}

def process_stripe_webhook_event(event):
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook event.")
    event_type = event.get("type")
    data = event.get("data")
    if not isinstance(event_type, str) or not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook event.")
    obj = data.get("object")
    if not isinstance(obj, dict):
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook object.")
    supported_types = {
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
    }
    if event_type not in supported_types:
        return {"ignored": True, "type": event_type}
    if event_type.startswith("checkout.session.") and not ALPHA_STRIPE_PAYMENT_LINK_ID:
        raise HTTPException(status_code=503, detail="Alpha payment link is not configured.")
    event_id = event.get("id")
    object_id = obj.get("id") if isinstance(obj, dict) else None
    if not isinstance(event_id, str) or not event_id or not isinstance(object_id, str) or not object_id:
        raise HTTPException(status_code=400, detail="Stripe event is missing an ID or object.")
    # Subscription.updated is repeatable for one subscription, so only the
    # immutable payment and terminal events get object-and-type deduplication.
    dedupe_key = f"{event_type}:{object_id}" if event_type != "customer.subscription.updated" else None
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                """INSERT INTO stripe_events
                   (event_id, object_id, event_type, dedupe_key, processed_at, outcome)
                   VALUES (?, ?, ?, ?, ?, 'processing')""",
                (event_id, object_id, event_type, dedupe_key, now_iso()),
            )
        except sqlite3.IntegrityError:
            return {"duplicate": True, "type": event_type}
        result = upsert_alpha_subscription_from_stripe(conn, obj, event_type)
        outcome = "unmatched" if result.get("unmatched") else "ignored" if result.get("ignored") else "processed"
        conn.execute("UPDATE stripe_events SET outcome = ? WHERE event_id = ?", (outcome, event_id))
        if outcome == "unmatched":
            _log.warning("Stripe payment event needs manual account review: type=%s, event=%s", event_type, event_id)
        return result


def has_active_alpha(user):
    """True only for a current Stripe subscription activated by a webhook."""
    user_id = user.get("google_id") if isinstance(user, dict) else user
    if not user_id:
        return False
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT metadata FROM alpha_subscriptions
               WHERE user_id = ? AND provider = 'stripe' AND status = 'active'
                 AND expires_at IS NOT NULL AND expires_at > ?""",
            (user_id, now_iso()),
        ).fetchall()
    for row in rows:
        try:
            if json.loads(row["metadata"] or "{}").get("source") == "stripe_webhook":
                return True
        except (TypeError, ValueError):
            pass
    return False

