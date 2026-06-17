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
from .config import VIRUSTOTAL_API_KEY
from .config import api_key
from .config import safe_browsing_url
from .lowlevel import normalize_url
from .lowlevel import virustotal_url_id
from .scoring import signal
from .security import validate_public_url

# =============================================================================
# THREAT TYPING & EXTERNAL REPUTATION (Google Safe Browsing / VirusTotal)
# =============================================================================
def threat_type_for_analysis(overall_risk, signals, ml_results=None):
    """Threat type label shown to the user.

    Prefer the most severe deterministic rule signal — those are explainable
    (e.g. "Domain Age", "VirusTotal Reputation"). Only fall back to the ML
    label when the overall risk is already high AND no rule signal qualifies,
    so a misfiring URL classifier can't single-handedly label a known-good
    domain as "Malicious QR".
    """
    if overall_risk == "safe":
        return "Benign"
    ml_signal_names = {"ML Risk Model", "ML Risk Model (EfficientNet)"}
    first_high = next((item for item in signals if item["severity"] == "high" and item["check"] not in ml_signal_names), None)
    if first_high:
        return first_high["check"]
    if isinstance(ml_results, dict) or ml_results is None:
        ml_results = [ml_results]
    # Only let ML drive the threat type when the overall risk is already
    # high — i.e. the blended score independently agrees this looks bad.
    if overall_risk == "high" and any(
        r and r.get("enabled") and (r.get("bucket") == "malicious" or r.get("label") == "Malicious")
        for r in ml_results
    ):
        return "Malicious QR"
    return "Suspicious QR"

def mock_analysis_response(target_url):
    normalized = normalize_url(target_url)
    signals = [
        signal("Domain Age", "8 days old", "high", "Domain registered less than 30 days ago, a common phishing indicator.", False),
        signal("VirusTotal Reputation", "12/90 engines flagged", "high", "Multiple reputation engines flagged this destination as unsafe.", False),
        signal("Redirect Chain", "2 redirect hops detected", "medium", "The QR destination redirects before reaching the final landing page.", False),
        signal("URL Shortener", "Shortener found in chain", "medium", "Shortened URLs can hide the true destination from users.", False),
        signal("TLD Risk", "Non-standard TLD .xyz", "low", "The domain uses a TLD that appears frequently in disposable campaigns.", False),
    ]
    verdict = "This QR code shows multiple high-risk signals, including a newly registered domain and reputation engine detections. Treat it as a likely phishing or wallet-drain attempt unless you can independently verify the sender."
    return {
        "url": normalized,
        "overallRisk": "high",
        "confidenceScore": 91,
        "verdict": verdict,
        "signals": signals,
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_url_reputation(target_url):
    try:
        target_url = validate_public_url(target_url)
    except SafeScanError as exc:
        return {
            "provider": "SafeScan URL Guard",
            "status": "BLOCKED",
            "matches": ["SSRF_BLOCKED"],
            "detail": str(exc)
        }
    if not api_key:
        return {
            "provider": "Google Safe Browsing",
            "status": "UNCONFIGURED",
            "matches": [],
            "detail": "Set GOOGLE_SAFE_BROWSING_API_KEY to enable live reputation checks."
        }

    payload = {
        "client" : {"clientId": "safescan-qr" , "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url" : target_url}]
        }
    }
    try:
        response = requests.post(safe_browsing_url, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as exc:
        return {
            "provider": "Google Safe Browsing",
            "status": "ERROR",
            "matches": [],
            "detail": f"Reputation lookup failed: {type(exc).__name__}"
        }

    matches = result.get("matches", [])
    return {
        "provider": "Google Safe Browsing",
        "status": "MALICIOUS" if matches else "CLEAR",
        "matches": [match.get("threatType", "UNKNOWN_THREAT") for match in matches],
        "detail": "Known unsafe URL match found." if matches else "No known unsafe URL match returned."
    }

def google_reputation_signal(target_url):
    reputation = check_url_reputation(target_url)
    if reputation["status"] == "MALICIOUS":
        result = ", ".join(reputation["matches"]) or "Unsafe match"
        return signal("Google Safe Browsing", result, "high", "Google Safe Browsing returned a known unsafe threat match.", False)
    if reputation["status"] == "CLEAR":
        return signal("Google Safe Browsing", "No matches", "low", "Google Safe Browsing did not return a known unsafe match.", True)
    return signal("Google Safe Browsing", reputation["status"], "low", reputation["detail"], True)



def virustotal_reputation_signal(target_url):
    if not VIRUSTOTAL_API_KEY:
        return signal("VirusTotal Reputation", "Not configured", "low", "Set VIRUSTOTAL_API_KEY to enable VirusTotal v3 reputation checks.", True)

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = virustotal_url_id(target_url)
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        if response.status_code == 404:
            scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url}, timeout=8)
            scan_response.raise_for_status()
            return signal("VirusTotal Reputation", "Scan submitted", "low", "VirusTotal did not have a cached verdict, so the URL was submitted for analysis.", True)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        return signal("VirusTotal Reputation", "Lookup failed", "low", f"VirusTotal lookup failed: {type(exc).__name__}", True)

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(value or 0) for value in stats.values()) or 90
    severity = "high" if flagged else "low"
    return signal(
        "VirusTotal Reputation",
        f"{flagged}/{total} engines flagged",
        severity,
        "VirusTotal engines flagged this URL." if flagged else "VirusTotal did not report malicious or suspicious engine detections.",
        flagged == 0
    )

