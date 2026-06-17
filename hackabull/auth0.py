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
from .config import AUTH0_AUDIENCES
from .config import AUTH0_ISSUER
from .config import _AUTH0_JWKS_CACHE
from .config import _AUTH0_JWKS_TTL_SECONDS

# =============================================================================
# AUTH0 / JWT TOKEN VERIFICATION
# =============================================================================
def _b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)

def _decode_jwt_unverified(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT.")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    return header, payload, parts

def _fetch_auth0_jwks():
    cached_keys = _AUTH0_JWKS_CACHE.get("keys")
    if cached_keys and (time.time() - _AUTH0_JWKS_CACHE["fetched_at"]) < _AUTH0_JWKS_TTL_SECONDS:
        return cached_keys
    response = requests.get(f"{AUTH0_ISSUER}.well-known/jwks.json", timeout=5)
    response.raise_for_status()
    keys = response.json().get("keys") or []
    _AUTH0_JWKS_CACHE["keys"] = keys
    _AUTH0_JWKS_CACHE["fetched_at"] = time.time()
    return keys

def _rsa_public_key_from_jwk(jwk):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e, n).public_key()

def verify_auth0_id_token(token):
    """Validate an Auth0-signed RS256 idToken via tenant JWKS. Returns claims."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    header, payload, parts = _decode_jwt_unverified(token)
    if header.get("alg") != "RS256":
        raise ValueError("Unsupported JWT algorithm.")
    kid = header.get("kid")
    if not kid:
        raise ValueError("JWT missing kid.")
    jwks = _fetch_auth0_jwks()
    matching = next((key for key in jwks if key.get("kid") == kid), None)
    if not matching:
        # JWKS may have rotated; force refresh once.
        _AUTH0_JWKS_CACHE["fetched_at"] = 0.0
        jwks = _fetch_auth0_jwks()
        matching = next((key for key in jwks if key.get("kid") == kid), None)
    if not matching:
        raise ValueError("No matching Auth0 signing key.")
    public_key = _rsa_public_key_from_jwk(matching)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _b64url_decode(parts[2])
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    issuer = payload.get("iss", "")
    if issuer.rstrip("/") != AUTH0_ISSUER.rstrip("/"):
        raise ValueError("JWT issuer mismatch.")
    audience = payload.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if AUTH0_AUDIENCES and not any(aud in AUTH0_AUDIENCES for aud in audiences if aud):
        raise ValueError("JWT audience mismatch.")
    now = int(time.time())
    if int(payload.get("exp", 0)) < now:
        raise ValueError("JWT expired.")
    if not payload.get("email"):
        raise ValueError("JWT missing email claim.")
    return payload

