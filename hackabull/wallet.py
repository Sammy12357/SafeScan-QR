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
from .audit import audit_log
from .audit import now_iso
from .config import BASE58_ALPHABET
from .config import SOLANA_RPC_URL
from .fraud import run_fraud_checks

# =============================================================================
# SOLANA WALLET VALIDATION & SIGNATURE VERIFICATION
# =============================================================================
def validate_wallet_address(address):
    clean = (address or "").strip()
    if not clean:
        return "", None
    if not is_valid_solana_address(clean):
        raise SafeScanError("Invalid Solana wallet address.", 400)
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT user_id FROM wallets WHERE address = ? AND verified = 1
            UNION
            SELECT email FROM scans WHERE wallet_address = ?
            LIMIT 1
            """,
            (clean, clean)
        ).fetchone()
    return clean, row[0] if row else None

def decode_base58(value):
    number = 0
    for char in value:
        number *= 58
        if char not in BASE58_ALPHABET:
            raise ValueError("Invalid base58 character")
        number += BASE58_ALPHABET.index(char)
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + encoded

def encode_base58(data):
    number = int.from_bytes(data, "big") if data else 0
    output = ""
    while number:
        number, remainder = divmod(number, 58)
        output = BASE58_ALPHABET[remainder] + output
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeroes + (output or "")

def is_valid_solana_address(address):
    clean = (address or "").strip()
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", clean):
        return False
    try:
        return len(decode_base58(clean)) == 32
    except ValueError:
        return False

def wallet_verification_message(nonce, email, issued_at, expires_at):
    return "\n".join([
        "SafeScan QR - Wallet Verification",
        "",
        "Sign this message to connect your wallet.",
        "This request will not trigger a blockchain transaction",
        "or cost any fees.",
        "",
        f"Nonce: {nonce}",
        f"Account: {email}",
        f"Issued: {issued_at}",
        f"Expires: {expires_at}",
    ])

def cleanup_wallet_nonces():
    cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM wallet_nonces WHERE expires_at < ? OR (used = 1 AND created_at < ?)",
            (now_iso(), cutoff)
        )

def expire_alpha_subscriptions():
    with get_conn() as conn:
        conn.execute(
            """UPDATE alpha_subscriptions
               SET status = 'expired', updated_at = ?
               WHERE status = 'active'
                 AND expires_at IS NOT NULL
                 AND expires_at <= ?""",
            (now_iso(), now_iso()),
        )

def get_verified_wallet(user_id):
    with get_conn() as conn:
        rows = user_scoped_select(conn, "wallets", "verified = 1")
        row = next((item for item in rows if item["user_id"] == user_id), None)
        if not row and not rls_user_id():
            row = conn.execute(
                "SELECT * FROM wallets WHERE user_id = ? AND verified = 1",
                (user_id,)
            ).fetchone()
    return dict(row) if row else None

def verify_solana_signature(wallet_address, signature, message):
    public_key_bytes = decode_base58(wallet_address)
    signature_bytes = decode_base58(signature)
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        raise ValueError("Invalid signature or public key length")
    Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
        signature_bytes,
        message.encode("utf-8")
    )

async def verify_wallet_on_chain(wallet_address, user_id):
    try:
        public_key = wallet_address
        balance_payload = {
            "jsonrpc": "2.0",
            "id": "safescan-balance",
            "method": "getBalance",
            "params": [public_key, {"commitment": "confirmed"}],
        }
        sig_payload = {
            "jsonrpc": "2.0",
            "id": "safescan-signatures",
            "method": "getSignaturesForAddress",
            "params": [public_key, {"limit": 5}],
        }
        balance_response, sig_response = await asyncio.gather(
            asyncio.to_thread(requests.post, SOLANA_RPC_URL, json=balance_payload, timeout=8),
            asyncio.to_thread(requests.post, SOLANA_RPC_URL, json=sig_payload, timeout=8),
        )
        balance_lamports = ((balance_response.json().get("result") or {}).get("value") or 0)
        signatures = sig_response.json().get("result") or []
        tx_count = len(signatures)
        wallet_age_days = None
        oldest = signatures[-1] if signatures else None
        if oldest and oldest.get("blockTime"):
            wallet_age_days = int((time.time() - int(oldest["blockTime"])) // (24 * 60 * 60))
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE wallets
                SET sol_balance = ?, tx_count = ?, wallet_age_days = ?, onchain_verified_at = ?
                WHERE address = ? AND user_id = ?
                """,
                (balance_lamports / 1_000_000_000, tx_count, wallet_age_days, now_iso(), wallet_address, user_id)
            )
        audit_log(
            "wallet.onchain_verified",
            actor_user_id=user_id,
            target_type="wallet",
            target_id=wallet_address[:8] + "...",
            metadata={"txCount": tx_count, "walletAgeDays": wallet_age_days}
        )
        if tx_count == 0 or (wallet_age_days is not None and wallet_age_days < 7):
            run_fraud_checks(
                "wallet_connect",
                user_id,
                None,
                {
                    "walletAddress": wallet_address,
                    "ip": "background_job",
                    "userAgent": "system",
                    "txCount": tx_count,
                    "walletAgeDays": wallet_age_days,
                }
            )
    except Exception as exc:
        print({"warning": "wallet_onchain_verification_failed", "error": str(exc)})

