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
from .config import DOMAIN_AGE_CHECK_ENABLED
from .config import HIGH_RISK_TLDS
from .config import HIGH_RISK_TWO_LABEL_TLDS
from .config import MALICIOUS_CONTRACT_BLOCKLIST
from .config import PROTECTED_BRANDS
from .domain_age import lookup_domain_age_result
from .lowlevel import normalize_url
from .scoring import signal

# =============================================================================
# TYPOSQUAT / DGA / DOMAIN INTELLIGENCE & CRYPTO-SCAM HEURISTICS
# =============================================================================
def _levenshtein(a, b):
    """Classic edit distance, used for typosquat detection on short labels."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]

def check_typosquat_signal(hostname):
    """Flag domains whose registrable label is a near-miss of a protected
    brand name (e.g. "robiox.com.py" vs. "roblox", "stleamcommuunity.com" vs.
    "steamcommunity") but isn't that brand's real domain - the classic
    credential-phishing setup."""
    domain = allowlist_registrable_domain(hostname)
    if not domain:
        return None
    label = domain.split(".")[0]
    if len(label) < 4:
        return None
    for brand, official in PROTECTED_BRANDS.items():
        if domain == official:
            continue
        distance = _levenshtein(label, brand)
        if distance == 0:
            continue
        max_len = max(len(label), len(brand))
        if distance <= 2 and (distance / max_len) <= 0.3:
            return signal(
                "Brand Impersonation",
                f"Looks like '{brand}' ({official})",
                "high",
                f"The domain '{domain}' closely resembles '{official}' (edit distance {distance}) but is not the official domain - a common setup for credential-phishing pages.",
                False,
            )
    return None

def _shannon_entropy(label):
    if not label:
        return 0.0
    counts = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(label)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def check_dga_signal(hostname):
    """Flag long, high-entropy domain labels consistent with malware-generated
    (DGA) or randomly-generated phishing domains, e.g.
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" (the WannaCry kill-switch
    domain)."""
    domain = allowlist_registrable_domain(hostname)
    if not domain:
        return None
    label = domain.split(".")[0]
    if len(label) < 24:
        return None
    entropy = _shannon_entropy(label)
    if entropy >= 3.3:
        return signal(
            "Algorithmically Generated Domain",
            f"{label} (entropy {entropy:.2f})",
            "medium",
            f"The domain label '{label}' is unusually long ({len(label)} characters) with high character randomness, consistent with malware-generated (DGA) or throwaway phishing domains.",
            False,
        )
    return None

def check_domain_intelligence(target_url):
    normalized = normalize_url(target_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return signal("Domain Intelligence", "No domain", "medium", "No valid domain could be extracted from the payload.", False)
    try:
        ipaddress.ip_address(hostname)
        return []
    except ValueError:
        pass

    tld_signal = None
    two_label_tld = "." + ".".join(hostname.rsplit(".", 2)[-2:]) if hostname.count(".") >= 2 else ""
    single_label_tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if two_label_tld in HIGH_RISK_TWO_LABEL_TLDS:
        tld_signal = signal("TLD Risk", f"High-risk TLD {two_label_tld}", "low", f"The domain uses {two_label_tld}, which appears often in disposable phishing campaigns.", False)
    elif single_label_tld in HIGH_RISK_TLDS:
        tld_signal = signal("TLD Risk", f"High-risk TLD {single_label_tld}", "low", f"The domain uses {single_label_tld}, which appears often in disposable phishing campaigns.", False)

    extra_signals = [s for s in (tld_signal, check_typosquat_signal(hostname), check_dga_signal(hostname)) if s]

    if not DOMAIN_AGE_CHECK_ENABLED:
        return extra_signals

    domain_age = lookup_domain_age_result(normalized)
    if domain_age["riskLevel"] == "unknown":
        detail = domain_age.get("riskDetail") or "Domain registration lookup could not be completed."
        base = signal("Domain Age", "Lookup unavailable", "low", detail, True)
        base["domainAge"] = domain_age
        return [base] + extra_signals

    age_days = domain_age["ageInDays"]
    signal_level = domain_age.get("signalLevel") or domain_age["riskLevel"]
    if signal_level == "established":
        return extra_signals
    severity = domain_age.get("severity") or ("high" if signal_level in ("very_new", "new") else ("medium" if signal_level == "young" else "low"))
    passed = severity == "low"
    registrar = domain_age.get("registrar") or "Unknown"
    source = domain_age.get("source") or "unknown"
    base = signal(
        "Domain Age",
        domain_age["ageLabel"],
        severity,
        f"{domain_age.get('riskDetail')} Source: {source}. Registrar: {registrar}.",
        passed
    )
    base["domainAge"] = domain_age
    return [base] + extra_signals

def check_crypto_pattern_signals(target_url):
    parsed = urlparse(target_url)
    haystack_parts = [target_url, parsed.query, parsed.fragment]
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        haystack_parts.append(value)
    haystack = " ".join(haystack_parts)
    lower = haystack.lower()
    found = []

    solana_patterns = ("transferchecked", "drainwallet", "sweeptokens", "sign-message", "signmessage")
    for pattern in solana_patterns:
        if pattern in lower:
            found.append(signal("Crypto Pattern", pattern, "high", f"Found {pattern}, a wallet-drain or token-transfer signature pattern.", False))

    if "approve" in lower and ("uint256" in lower or "ffffffffffffffff" in lower or "max" in lower):
        found.append(signal("Ethereum Approval Pattern", "approve max uint256", "high", "The payload appears to request a maximum token approval.", False))

    # EIP-2612 / Permit2 off-chain "permit" signatures are the dominant
    # technique used by modern drainer kits (Inferno, Pink, Angel Drainer):
    # the victim signs a gasless message granting the attacker a token
    # allowance, with no on-chain "approve" call to flag.
    permit_patterns = ("permit2", "eth_signtypedata", "safetransferfrom", "increaseallowance")
    for pattern in permit_patterns:
        if pattern in lower:
            found.append(signal("Token Permit Pattern", pattern, "high", f"Found {pattern}, an off-chain token permit/transfer signature commonly used by wallet-drainer kits.", False))
    if re.search(r"\bpermit\b", lower):
        found.append(signal("Token Permit Pattern", "permit", "high", "Found a 'permit' signature request, a gasless token-approval pattern commonly used by wallet-drainer kits.", False))

    # NFT-collection drains: granting an operator blanket control of every
    # token via setApprovalForAll.
    if "setapprovalforall" in lower:
        found.append(signal("NFT Approval Pattern", "setApprovalForAll", "high", "The payload appears to request blanket operator approval over an NFT collection.", False))

    # WalletConnect pairing URIs embedded in QR codes can silently propose a
    # malicious session to whatever wallet scans them.
    if "wc:" in lower:
        found.append(signal("WalletConnect Pairing URI", "wc: URI detected", "medium", "The payload is a WalletConnect pairing URI. Verify the requesting site before approving the session.", False))

    base58_pattern = r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![A-Za-z0-9])"
    base58_hits = re.findall(base58_pattern, parsed.query + " " + parsed.fragment)
    if base58_hits:
        found.append(signal("Solana Address Placement", f"{len(base58_hits)} address-like value(s)", "high", "Base58 wallet addresses appear inside query parameters or hash fragments.", False))

    for blocked in MALICIOUS_CONTRACT_BLOCKLIST:
        if blocked.lower() in lower:
            found.append(signal("Known Malicious Contract", blocked, "high", "The payload contains an address from the SafeScan MVP blocklist.", False))

    if not found:
        found.append(signal("Crypto Pattern", "No wallet-drain pattern found", "low", "No known Solana/Ethereum wallet-drain signature patterns were detected.", True))
    return found

