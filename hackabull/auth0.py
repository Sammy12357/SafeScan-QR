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
import binascii
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
import jwt
from jwt.exceptions import PyJWTError
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
from .config import AUTH0_AUDIENCES
from .config import AUTH0_ISSUER
from .config import _AUTH0_JWKS_CACHE
from .config import _AUTH0_JWKS_TTL_SECONDS

# =============================================================================
# AUTH0 / JWT TOKEN VERIFICATION
# =============================================================================
def _decode_jwt_unverified(token):
    """Read only the issuer hint for provider dispatch; never authenticate it."""
    if not isinstance(token, str) or len(token) > 16_384:
        raise ValueError("Invalid JWT size.")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT.")
    try:
        header = jwt.get_unverified_header(token)
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    except (PyJWTError, ValueError, UnicodeDecodeError, binascii.Error, RecursionError) as exc:
        raise ValueError("Malformed JWT.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Malformed JWT payload.")
    return header, payload, parts

def _fetch_auth0_jwks():
    now = time.time()
    cached_keys = _AUTH0_JWKS_CACHE.get("keys")
    if cached_keys and (now - _AUTH0_JWKS_CACHE["fetched_at"]) < _AUTH0_JWKS_TTL_SECONDS:
        return cached_keys
    # An unknown kid never bypasses this cooldown. Set it before the fetch so
    # a failed tenant request cannot be amplified by repeated bad tokens.
    if now - _AUTH0_JWKS_CACHE.get("last_attempt_at", 0.0) < _AUTH0_JWKS_TTL_SECONDS:
        raise ValueError("Auth0 signing keys temporarily unavailable.")
    _AUTH0_JWKS_CACHE["last_attempt_at"] = now
    try:
        response = requests.get(f"{AUTH0_ISSUER}.well-known/jwks.json", timeout=5)
        response.raise_for_status()
        keys = response.json().get("keys") or []
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Auth0 signing keys unavailable.") from exc
    if not isinstance(keys, list) or len(keys) > 32:
        raise ValueError("Invalid Auth0 signing keys.")
    _AUTH0_JWKS_CACHE["keys"] = keys
    _AUTH0_JWKS_CACHE["fetched_at"] = now
    return keys

def verify_auth0_id_token(token):
    """Validate an Auth0-signed RS256 idToken via tenant JWKS. Returns claims."""
    if not isinstance(token, str) or len(token) > 16_384:
        raise ValueError("Invalid JWT size.")
    try:
        header = jwt.get_unverified_header(token)
    except PyJWTError as exc:
        raise ValueError("Malformed JWT.") from exc
    if header.get("alg") != "RS256":
        raise ValueError("Unsupported JWT algorithm.")
    if header.get("typ") != "JWT":
        raise ValueError("Unsupported JWT type.")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > 128:
        raise ValueError("JWT missing kid.")
    if not AUTH0_AUDIENCES:
        raise ValueError("Auth0 audience is not configured.")
    keys = _fetch_auth0_jwks()
    try:
        jwk_set = jwt.PyJWKSet.from_dict({"keys": keys})
        matching = next((key for key in jwk_set.keys if key.key_id == kid), None)
    except (PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid Auth0 signing keys.") from exc
    if matching is None or matching.algorithm_name != "RS256":
        raise ValueError("No matching Auth0 signing key.")
    try:
        payload = jwt.decode(
            token, matching.key, algorithms=["RS256"], audience=tuple(AUTH0_AUDIENCES),
            issuer=AUTH0_ISSUER, leeway=60,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except PyJWTError as exc:
        raise ValueError("Invalid Auth0 ID token.") from exc
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise ValueError("JWT missing subject.")
    if not isinstance(payload.get("email"), str) or not payload["email"].strip():
        raise ValueError("JWT missing email claim.")
    return payload

