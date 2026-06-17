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
from .audit import SafeScanError
from .audit import now_iso
from .auth import get_session_user
from .config import ALPHA_SOLANA_ACCESS_DAYS
from .config import ALPHA_SOLANA_AMOUNT_SOL
from .config import ALPHA_SOLANA_LABEL
from .config import ALPHA_SOLANA_MESSAGE
from .config import ALPHA_SOLANA_PRICE_USD
from .config import ALPHA_SOLANA_QUOTE_TTL_SECONDS
from .config import ALPHA_SOLANA_RECIPIENT
from .config import SOLANA_RPC_URL
from .config import SOLANA_USD_PRICE_FALLBACK
from .config import SOLANA_USD_PRICE_URL
from .pipeline import decimal_text
from .request_helpers import make_id
from .wallet import encode_base58
from .wallet import is_valid_solana_address

# =============================================================================
# SOLANA ALPHA-SUBSCRIPTION PRICING & ON-CHAIN PAYMENT VERIFICATION
# =============================================================================
def solana_amount_to_lamports(amount):
    return int((amount * Decimal("1000000000")).to_integral_value(rounding="ROUND_CEILING"))

def solana_lamports_to_amount(lamports):
    return Decimal(int(lamports)) / Decimal("1000000000")

def fetch_sol_usd_price():
    if SOLANA_USD_PRICE_URL:
        try:
            response = requests.get(SOLANA_USD_PRICE_URL, timeout=6)
            response.raise_for_status()
            body = response.json()
            price = body.get("solana", {}).get("usd") if isinstance(body, dict) else None
            if price:
                value = Decimal(str(price))
                if value > 0:
                    return value
        except Exception:
            pass
    if SOLANA_USD_PRICE_FALLBACK:
        try:
            value = Decimal(SOLANA_USD_PRICE_FALLBACK)
            if value > 0:
                return value
        except InvalidOperation:
            pass
    return None

def fallback_alpha_solana_lamports():
    if not ALPHA_SOLANA_AMOUNT_SOL:
        return 0, ""
    try:
        amount = Decimal(ALPHA_SOLANA_AMOUNT_SOL)
    except InvalidOperation as exc:
        raise SafeScanError("ALPHA_SOLANA_AMOUNT_SOL is invalid.", 500) from exc
    if amount <= 0:
        return 0, ""
    return solana_amount_to_lamports(amount), decimal_text(amount)

def create_alpha_solana_quote():
    if ALPHA_SOLANA_PRICE_USD <= 0:
        raise SafeScanError("ALPHA_SOLANA_PRICE_USD must be greater than 0.", 500)
    sol_usd = fetch_sol_usd_price()
    if sol_usd:
        amount_sol = ALPHA_SOLANA_PRICE_USD / sol_usd
        lamports = solana_amount_to_lamports(amount_sol)
        amount_sol_text = decimal_text(solana_lamports_to_amount(lamports))
        return {
            "amountUsd": decimal_text(ALPHA_SOLANA_PRICE_USD, places=2),
            "solUsdPrice": decimal_text(sol_usd, places=6),
            "amountSol": amount_sol_text,
            "amountLamports": lamports,
            "quoteExpiresAt": (datetime.utcnow() + timedelta(seconds=ALPHA_SOLANA_QUOTE_TTL_SECONDS)).isoformat() + "Z",
        }
    fallback_lamports, fallback_amount = fallback_alpha_solana_lamports()
    if fallback_lamports:
        return {
            "amountUsd": decimal_text(ALPHA_SOLANA_PRICE_USD, places=2),
            "solUsdPrice": None,
            "amountSol": fallback_amount,
            "amountLamports": fallback_lamports,
            "quoteExpiresAt": (datetime.utcnow() + timedelta(seconds=ALPHA_SOLANA_QUOTE_TTL_SECONDS)).isoformat() + "Z",
        }
    raise SafeScanError("SOL/USD price is unavailable and no fallback SOL amount is configured.", 503)

def normalize_alpha_solana_quote(row):
    if not row:
        return None
    data = dict(row)
    return {
        "reference": data.get("reference"),
        "recipient": data.get("recipient"),
        "amountUsd": data.get("amountUsd") or data.get("amount_usd"),
        "solUsdPrice": data.get("solUsdPrice") or data.get("sol_usd_price"),
        "amountSol": data.get("amountSol") or data.get("amount_sol"),
        "amountLamports": data.get("amountLamports") or data.get("amount_lamports"),
        "quoteExpiresAt": data.get("quoteExpiresAt") or data.get("quote_expires_at"),
        "status": data.get("status"),
    }

def alpha_subscription_expires_at():
    return (datetime.utcnow() + timedelta(days=ALPHA_SOLANA_ACCESS_DAYS)).isoformat() + "Z"

def get_or_create_alpha_solana_reference(user):
    if not user:
        return None
    if not ALPHA_SOLANA_RECIPIENT:
        return None
    if not is_valid_solana_address(ALPHA_SOLANA_RECIPIENT):
        raise SafeScanError("ALPHA_SOLANA_RECIPIENT is not a valid Solana address.", 500)
    now = now_iso()
    with get_conn() as conn:
        row = conn.execute(
            """SELECT * FROM alpha_solana_payment_references
               WHERE user_id = ? AND recipient = ? AND status = 'pending'
                 AND quote_expires_at IS NOT NULL AND quote_expires_at > ?
               ORDER BY created_at DESC LIMIT 1""",
            (user["google_id"], ALPHA_SOLANA_RECIPIENT, now),
        ).fetchone()
        if row:
            return normalize_alpha_solana_quote(row)
        conn.execute(
            """UPDATE alpha_solana_payment_references
               SET status = 'expired_' || substr(reference, -8), updated_at = ?
               WHERE user_id = ? AND recipient = ? AND status = 'pending'
                 AND quote_expires_at IS NOT NULL AND quote_expires_at <= ?""",
            (now, user["google_id"], ALPHA_SOLANA_RECIPIENT, now),
        )
        quote_data = create_alpha_solana_quote()
        reference = encode_base58(os.urandom(32))
        conn.execute(
            """INSERT INTO alpha_solana_payment_references
               (id, user_id, email, reference, recipient, amount_sol, amount_usd,
                sol_usd_price, amount_lamports, quote_expires_at, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (
                make_id("solpay"),
                user["google_id"],
                user["email"],
                reference,
                ALPHA_SOLANA_RECIPIENT,
                quote_data["amountSol"],
                quote_data["amountUsd"],
                quote_data["solUsdPrice"],
                quote_data["amountLamports"],
                quote_data["quoteExpiresAt"],
                now,
                now,
            ),
        )
    return {**quote_data, "reference": reference, "recipient": ALPHA_SOLANA_RECIPIENT, "status": "pending"}

def alpha_solana_quote_for_user(user):
    quote_row = get_or_create_alpha_solana_reference(user)
    if not quote_row:
        return None
    return quote_row

def alpha_solana_pay_url(request: Request | None = None):
    if not ALPHA_SOLANA_RECIPIENT:
        return ""

    params = []
    quote_row = None
    if request:
        quote_row = alpha_solana_quote_for_user(get_session_user(request))
    if quote_row:
        params.append(("amount", str(quote_row["amountSol"])))
        params.append(("reference", str(quote_row["reference"])))
    elif ALPHA_SOLANA_AMOUNT_SOL:
        params.append(("amount", ALPHA_SOLANA_AMOUNT_SOL))
    if ALPHA_SOLANA_LABEL:
        params.append(("label", ALPHA_SOLANA_LABEL))
    if ALPHA_SOLANA_MESSAGE:
        params.append(("message", ALPHA_SOLANA_MESSAGE))
    params.append(("memo", "SafeScan Alpha"))

    query = "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in params)
    return f"solana:{ALPHA_SOLANA_RECIPIENT}?{query}" if query else f"solana:{ALPHA_SOLANA_RECIPIENT}"

def solana_rpc(method, params):
    response = requests.post(
        SOLANA_RPC_URL,
        json={"jsonrpc": "2.0", "id": f"safescan-{method}", "method": method, "params": params},
        timeout=10,
    )
    response.raise_for_status()
    body = response.json()
    if body.get("error"):
        raise SafeScanError(f"Solana RPC error: {body['error'].get('message', 'unknown error')}", 502)
    return body.get("result")

def transaction_account_keys(transaction):
    message = ((transaction or {}).get("transaction") or {}).get("message") or {}
    keys = []
    for item in message.get("accountKeys") or []:
        if isinstance(item, str):
            keys.append(item)
        elif isinstance(item, dict):
            keys.append(item.get("pubkey", ""))
    return keys

def transaction_recipient_delta_lamports(transaction, recipient):
    keys = transaction_account_keys(transaction)
    try:
        recipient_index = keys.index(recipient)
    except ValueError:
        return 0
    meta = (transaction or {}).get("meta") or {}
    pre = meta.get("preBalances") or []
    post = meta.get("postBalances") or []
    if recipient_index >= len(pre) or recipient_index >= len(post):
        return 0
    return int(post[recipient_index]) - int(pre[recipient_index])

def verify_alpha_solana_payment(reference):
    """Confirm an Alpha subscription was actually paid on-chain.

    Looks up the pending Solana Pay quote for ``reference``, queries the chain
    for a matching transfer of the expected lamport amount to our wallet, and
    activates the subscription when found. Prevents crediting unpaid quotes.
    """
    with get_conn() as conn:
        quote_row = conn.execute(
            "SELECT * FROM alpha_solana_payment_references WHERE reference = ? AND status = 'pending'",
            (reference,),
        ).fetchone()
    if not quote_row:
        raise SafeScanError("No pending Solana payment quote was found.", 400)
    required_lamports = int(quote_row["amount_lamports"] or 0)
    if not ALPHA_SOLANA_RECIPIENT or not required_lamports:
        raise SafeScanError("Solana payment is not configured.", 400)
    if quote_row["quote_expires_at"] and quote_row["quote_expires_at"] <= now_iso():
        raise SafeScanError("This Solana payment quote expired. Open the payment page to generate a fresh quote.", 400)
    signatures = solana_rpc("getSignaturesForAddress", [reference, {"limit": 12, "commitment": "confirmed"}]) or []
    for item in signatures:
        signature = item.get("signature")
        if not signature or item.get("err"):
            continue
        tx = solana_rpc(
            "getTransaction",
            [signature, {"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0}],
        )
        keys = transaction_account_keys(tx)
        if reference not in keys or ALPHA_SOLANA_RECIPIENT not in keys:
            continue
        if transaction_recipient_delta_lamports(tx, ALPHA_SOLANA_RECIPIENT) >= required_lamports:
            return signature
    return ""

def record_alpha_solana_subscription(user, reference, signature):
    purchased_at = now_iso()
    expires_at = alpha_subscription_expires_at()
    metadata = {
        "source": "solana_payment_verification",
        "reference": reference,
        "signature": signature,
        "recipient": ALPHA_SOLANA_RECIPIENT,
    }
    with get_conn() as conn:
        quote_row = conn.execute(
            "SELECT * FROM alpha_solana_payment_references WHERE user_id = ? AND reference = ?",
            (user["google_id"], reference),
        ).fetchone()
        if quote_row:
            metadata.update({
                "amountUsd": quote_row["amount_usd"],
                "solUsdPrice": quote_row["sol_usd_price"],
                "amountSol": quote_row["amount_sol"],
                "amountLamports": quote_row["amount_lamports"],
                "quoteExpiresAt": quote_row["quote_expires_at"],
            })
        conn.execute(
            """UPDATE alpha_solana_payment_references
               SET status = 'verified_' || substr(reference, -8), signature = ?, updated_at = ?, expires_at = ?
               WHERE user_id = ? AND reference = ?""",
            (signature, purchased_at, expires_at, user["google_id"], reference),
        )
        conn.execute(
            """
            INSERT INTO alpha_subscriptions
                (id, user_id, email, tier, provider, status, purchased_at,
                 client_reference_id, metadata, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, 'alpha_premium', 'solana', 'active', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, tier, provider) DO UPDATE SET
                email = excluded.email,
                status = 'active',
                client_reference_id = excluded.client_reference_id,
                metadata = excluded.metadata,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            """,
            (
                make_id("sub"),
                user["google_id"],
                user["email"],
                purchased_at,
                reference,
                json.dumps(metadata),
                expires_at,
                purchased_at,
                purchased_at,
            ),
        )
    return {"email": user["email"], "purchased_at": purchased_at, "expires_at": expires_at, "signature": signature}

