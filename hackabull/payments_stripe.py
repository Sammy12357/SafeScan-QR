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
from .config import STRIPE_WEBHOOK_SECRET
from .request_helpers import hash_ip
from .request_helpers import make_id
from .request_helpers import request_ip

# =============================================================================
# STRIPE SUBSCRIPTION PAYMENTS & WEBHOOKS
# =============================================================================
def alpha_stripe_checkout_url(request: Request):
    if not ALPHA_STRIPE_PAYMENT_LINK:
        return ""

    user = get_session_user(request)
    params = []
    if user:
        if user.get("email"):
            params.append(("prefilled_email", user["email"]))
        if user.get("google_id"):
            params.append(("client_reference_id", user["google_id"]))

    if not params:
        return ALPHA_STRIPE_PAYMENT_LINK

    separator = "&" if "?" in ALPHA_STRIPE_PAYMENT_LINK else "?"
    return f"{ALPHA_STRIPE_PAYMENT_LINK}{separator}{urlencode(params)}"

def record_alpha_subscription_purchase(request: Request, provider="stripe"):
    user = get_session_user(request)
    if not user:
        return None

    purchased_at = now_iso()
    metadata = {
        "source": "alpha_success_page",
        "ipHash": hash_ip(request_ip(request)),
        "userAgent": request.headers.get("user-agent", ""),
    }
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO alpha_subscriptions
                (id, user_id, email, tier, provider, status, purchased_at,
                 stripe_payment_link, client_reference_id, metadata, created_at, updated_at)
            VALUES (?, ?, ?, 'alpha_premium', ?, 'active', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, tier, provider) DO UPDATE SET
                email = excluded.email,
                status = 'active',
                stripe_payment_link = excluded.stripe_payment_link,
                client_reference_id = excluded.client_reference_id,
                metadata = excluded.metadata,
                updated_at = excluded.updated_at
            """,
            (
                make_id("sub"),
                user["google_id"],
                user["email"],
                provider,
                purchased_at,
                ALPHA_STRIPE_PAYMENT_LINK if provider == "stripe" else None,
                user["google_id"],
                json.dumps(metadata),
                purchased_at,
                purchased_at,
            ),
        )
    return {**user, "purchased_at": purchased_at}

def verify_stripe_webhook_signature(payload: bytes, signature_header: str):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Stripe webhook secret is not configured.")
    parts = {}
    for item in (signature_header or "").split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts.setdefault(key, []).append(value)
    timestamp = (parts.get("t") or [""])[0]
    signatures = parts.get("v1") or []
    if not timestamp or not signatures:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature header.")
    try:
        signed_payload = timestamp.encode("utf-8") + b"." + payload
        expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.") from exc
    if not any(hmac.compare_digest(expected, signature) for signature in signatures):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature.")

def stripe_event_email(obj):
    return (
        obj.get("customer_email")
        or (obj.get("customer_details") or {}).get("email")
        or (obj.get("metadata") or {}).get("email")
        or ""
    ).strip().lower()

def stripe_user_identity(email, client_reference_id=None):
    normalized_email = (email or "").strip().lower()
    with get_conn() as conn:
        row = None
        if client_reference_id:
            row = conn.execute("SELECT google_id, email FROM users WHERE google_id = ?", (client_reference_id,)).fetchone()
        if not row and normalized_email:
            row = conn.execute("SELECT google_id, email FROM users WHERE lower(email) = ?", (normalized_email,)).fetchone()
    if row:
        return row["google_id"], (row["email"] or normalized_email)
    fallback_id = client_reference_id or normalized_email or "stripe_unknown"
    return fallback_id, normalized_email

def upsert_alpha_subscription_from_stripe(obj, event_type):
    metadata = obj.get("metadata") or {}
    email = stripe_event_email(obj)
    client_reference_id = obj.get("client_reference_id") or metadata.get("client_reference_id")
    stripe_customer_id = obj.get("customer")
    stripe_subscription_id = obj.get("subscription") or obj.get("id")
    existing_identity = None
    if not email and (stripe_subscription_id or stripe_customer_id):
        with get_conn() as conn:
            existing_identity = conn.execute(
                """SELECT user_id, email FROM alpha_subscriptions
                   WHERE (stripe_subscription_id = ? AND ? IS NOT NULL)
                      OR (stripe_customer_id = ? AND ? IS NOT NULL)
                   ORDER BY updated_at DESC LIMIT 1""",
                (stripe_subscription_id, stripe_subscription_id, stripe_customer_id, stripe_customer_id),
            ).fetchone()
    if existing_identity:
        user_id, stored_email = existing_identity["user_id"], existing_identity["email"]
    else:
        user_id, stored_email = stripe_user_identity(email, client_reference_id)
    event_status = obj.get("status") or "active"
    cancel_at_period_end = 1 if obj.get("cancel_at_period_end") else 0
    current_period_start = iso_from_unix_timestamp(obj.get("current_period_start"))
    current_period_end = iso_from_unix_timestamp(obj.get("current_period_end"))
    canceled_at = iso_from_unix_timestamp(obj.get("canceled_at"))
    purchased_at = iso_from_unix_timestamp(obj.get("created")) or now_iso()

    if event_type == "checkout.session.completed":
        event_status = "active" if obj.get("payment_status") in ("paid", "no_payment_required", None) else event_status
    elif event_type == "invoice.paid":
        event_status = "active"
    elif event_type == "customer.subscription.deleted":
        event_status = "canceled"
        canceled_at = canceled_at or now_iso()
    elif event_type == "customer.subscription.updated" and event_status == "canceled":
        canceled_at = canceled_at or now_iso()

    expires_at = canceled_at if event_status == "canceled" else current_period_end
    updated_at = now_iso()
    webhook_metadata = {
        "source": "stripe_webhook",
        "eventType": event_type,
        "stripeObjectId": obj.get("id"),
        "rawStatus": obj.get("status"),
    }

    with get_conn() as conn:
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
    event_type = event.get("type")
    obj = (event.get("data") or {}).get("object") or {}
    if event_type in {
        "checkout.session.completed",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
    }:
        return upsert_alpha_subscription_from_stripe(obj, event_type)
    return {"ignored": True, "type": event_type}

