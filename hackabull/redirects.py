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
from .config import URL_SHORTENERS
from .scoring import signal
from .security import follow_safe_redirects

# =============================================================================
# REDIRECT TRACING (follow & inspect a URL's redirect chain)
# =============================================================================
def inspect_redirects(target_url):
    try:
        responses = follow_safe_redirects(target_url)
    except SafeScanError as exc:
        return {
            "status": "BLOCKED",
            "count": 0,
            "final_url": target_url,
            "detail": str(exc)
        }
    except requests.RequestException as exc:
        return {
            "status": "ERROR",
            "count": 0,
            "final_url": target_url,
            "detail": f"Redirect inspection failed: {type(exc).__name__}"
        }

    response = responses[-1]
    return {
        "status": "OK",
        "count": max(0, len(responses) - 1),
        "final_url": response.url,
        "detail": "Redirect chain inspected."
    }

def trace_redirect_chain(target_url):
    try:
        all_responses = follow_safe_redirects(target_url)
    except SafeScanError as exc:
        return {
            "signal": signal("Redirect Chain", "Blocked internal redirect target", "high", str(exc), False),
            "redirectChain": []
        }
    except requests.TooManyRedirects:
        return {
            "signal": signal("Redirect Chain", "More than 10 redirects", "high", "The URL exceeded the 10-hop redirect limit.", False),
            "redirectChain": []
        }
    except requests.RequestException as exc:
        return {
            "signal": signal("Redirect Chain", "Inspection failed", "low", f"Redirect inspection failed: {type(exc).__name__}", True),
            "redirectChain": []
        }

    def _site_key(host):
        """Approximate eTLD+1: strip common subdomain prefixes (www., m., mobile.)
        and reduce to the last two dot-labels so apex/www/mobile variants of the
        same site compare equal."""
        h = (host or "").lower().strip(".")
        for prefix in ("www.", "m.", "mobile.", "amp.", "en.", "us."):
            if h.startswith(prefix):
                h = h[len(prefix):]
                break
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else h

    # SSO / federated-auth indicators. If any hop matches one of these, the
    # cross-domain redirect is almost certainly a legitimate auth bounce
    # (school portal -> idp -> portal, app -> oauth provider -> app, etc.)
    # rather than a wallet-drain or phishing chain.
    SSO_HOST_PREFIXES = ("idp.", "auth.", "sso.", "login.", "accounts.", "id.", "signin.", "secure.")
    SSO_HOST_SUFFIXES = (
        ".okta.com", ".auth0.com", ".onelogin.com", ".duosecurity.com",
        ".pingidentity.com", ".ping.cloud", ".cas.edu",
        "accounts.google.com", "login.microsoftonline.com",
        "login.live.com", "appleid.apple.com", "login.yahoo.com",
        "github.com/login", "shibboleth",
    )
    SSO_PATH_TOKENS = (
        "/login", "/signin", "/sign-in", "/sso", "/saml", "/openid",
        "/oauth", "/oauth2", "/auth/callback", "/cas/login", "/idp",
        "/shibboleth", "/adfs/ls", "/auth/realms/",
    )

    def _looks_like_sso(host, path):
        host_l = (host or "").lower()
        path_l = (path or "").lower()
        if any(host_l.startswith(p) for p in SSO_HOST_PREFIXES):
            return True
        if any(host_l.endswith(s) or s in host_l for s in SSO_HOST_SUFFIXES):
            return True
        if any(tok in path_l for tok in SSO_PATH_TOKENS):
            return True
        return False

    original_domain = urlparse(target_url).hostname or ""
    original_site = _site_key(original_domain)
    chain = []
    domain_changed = False
    has_shortener = False
    saw_sso_hop = False
    returned_to_origin = False
    for item in all_responses:
        item_url = item.url
        parsed = urlparse(item_url)
        domain = parsed.hostname or ""
        # Only flag a "domain change" when the redirect actually leaves the
        # site (e.g. bit.ly -> malware.tk), not for apex->www or m.* variants
        # of the same eTLD+1.
        site = _site_key(domain)
        changed = bool(original_site and domain and site != original_site)
        domain_changed = domain_changed or changed
        has_shortener = has_shortener or domain.lower().removeprefix("www.") in URL_SHORTENERS
        if _looks_like_sso(domain, parsed.path):
            saw_sso_hop = True
        if original_site and site == original_site and changed is False:
            # We returned to the original site at some hop (typical for
            # SSO: portal -> idp -> portal).
            returned_to_origin = True
        chain.append({"url": item_url, "domain": domain, "statusCode": item.status_code, "domainChanged": changed})

    hop_count = max(0, len(chain) - 1)
    # SSO is only "recognized" when it's a typical bounce: at least one hop
    # to an identity provider, returns to the original site, no shortener,
    # and short overall (3 hops max). Anything more elaborate stays graded
    # by the normal rules below.
    sso_flow = (
        saw_sso_hop and returned_to_origin and not has_shortener and hop_count <= 3
    )
    # Severity gradient:
    #   - shorteners or >2 hops or (2 hops AND cross-domain): high
    #   - single cross-domain hop (e.g. twitter.com -> x.com): medium
    #   - hops within the same site (apex<->www, etc.): low
    is_high = has_shortener or hop_count > 2 or (hop_count >= 2 and domain_changed)
    is_medium = (hop_count >= 1 and domain_changed) or hop_count == 2
    # Recognized SSO/auth bounces are normal web auth, not phishing -
    # treat the whole chain as low severity (passes).
    if sso_flow:
        is_high = False
        is_medium = False
    severity = "high" if is_high else ("medium" if is_medium else "low")
    suspicious = is_high or is_medium
    details = []
    if hop_count > 2:
        details.append("more than 2 redirect hops")
    if domain_changed and not sso_flow:
        details.append("final or intermediate domain differs from the original")
    if has_shortener:
        details.append("known URL shortener appears in the chain")
    if sso_flow:
        details.append("recognized SSO/auth bounce (cross-domain hop into a federated identity provider and back)")
    if sso_flow:
        description = f"Recognized SSO/auth bounce ({hop_count} hop(s) into a federated identity provider and back)."
        result_label = f"{hop_count} hop(s) (SSO)"
    elif not details:
        description = "Redirect chain is simple."
        result_label = f"{hop_count} hop(s)"
    else:
        description = "Suspicious redirect pattern: " + ", ".join(details) + "."
        result_label = f"{hop_count} hop(s)"
    return {
        "signal": signal("Redirect Chain", result_label, severity, description, not suspicious),
        "redirectChain": chain
    }

