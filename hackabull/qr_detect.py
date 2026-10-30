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
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl, unquote
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
from .config import ML_SIGNAL_VISIBLE
from .lowlevel import normalize_url
from .pipeline import analyze_full_pipeline
from .pipeline import is_url_like
from .qr_image import blend_ml_score
from .qr_image import classify_qr_with_ml
from .qr_image import ml_signal_from_result
from .redirects import inspect_redirects
from .reputation import check_url_reputation
from .reputation import threat_type_for_analysis
from .request_helpers import get_cached_result
from .request_helpers import save_to_cache
from .scoring import clamp_score
from .scoring import risk_from_score
from .scoring import risk_reason
from .scoring import status_from_risk
from .security import validate_public_url
from .audit import SafeScanError

# =============================================================================
# QR PAYLOAD DETECTION & ANALYSIS
# Classifies a decoded payload (URL, wifi, vcard, crypto address, etc.) and
# routes it to the right analyzer.
# =============================================================================
MAX_EMBEDDED_URLS = 16


def extract_urls(text):
    """Find distinct HTTP(S) destinations, including percent-encoded links.

    QR action formats often put a URL in a field or encode it once or twice in
    an app fallback parameter. Keep source order and never silently inspect
    only the first destination.
    """
    found = []
    seen = set()
    candidate = text or ""
    for _ in range(3):
        for match in re.finditer(r"https?://[^\s<>'\"\\\[\]{};]+", candidate, flags=re.IGNORECASE):
            url = match.group(0).rstrip(".,;)")
            if url and url not in seen:
                seen.add(url)
                found.append(url)
        decoded = unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    return found

def _truncate_description(value, limit=90):
    value = (value or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."

def _qr_field_value(payload, field):
    searchable = payload[5:] if payload.upper().startswith("WIFI:") else payload
    match = re.search(rf"(?:^|[;\r\n]){re.escape(field)}:([^;\r\n]*)", searchable, flags=re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).replace("\\;", ";").strip()


def local_embedded_url_risk(url):
    """Inspect URL-shaped text in a private QR without DNS or network calls."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return 80, risk_reason("Malformed embedded link", "high", "An embedded link has an invalid host and was not opened or sent to a provider.")
    if not host or parsed.username is not None or parsed.password is not None:
        return 80, risk_reason("Deceptive embedded link", "high", "An embedded link contains a missing host or user-info camouflage.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if host == "localhost" or host.endswith(".local") or (address and not address.is_global):
        return 80, risk_reason("Internal embedded link", "high", "An embedded link points at a local or non-public address.")
    if any(marker in url.lower() for marker in ("drain", "seed", "recovery", "password", "sign-message", "permit")):
        return 70, risk_reason("Sensitive embedded link wording", "high", "An embedded link contains wallet-drain or credential-related wording.")
    if "xn--" in host:
        return 65, risk_reason("Encoded embedded domain", "medium", "An embedded link uses an internationalized domain encoding that should be reviewed.")
    if parsed.scheme != "https":
        return 55, risk_reason("Non-HTTPS embedded link", "medium", "An embedded link does not use HTTPS.")
    return 45, risk_reason("Embedded link not fetched", "medium", "A URL-shaped value was found, but its destination was not contacted because this QR may contain private data.")

def describe_qr_action(payload_type, normalized):
    if payload_type == "URL":
        parsed = urlparse(normalized)
        host = parsed.hostname or normalized
        path = parsed.path or "/"
        if any(marker in normalized.lower() for marker in (".apk", ".exe", ".dmg", ".pkg", ".zip", "download")):
            return f"Open a browser link on {host} that appears to start or offer a download."
        if any(marker in normalized.lower() for marker in ("approve", "permit", "signature", "sign-message", "claim", "airdrop")):
            return f"Open a browser link on {host} that may lead into a wallet, claim, approval, or signature flow."
        return f"Open a browser link on {host}{_truncate_description(path, 48)}."
    if payload_type == "Wi-Fi":
        ssid = _qr_field_value(normalized, "S")
        auth = _qr_field_value(normalized, "T") or "unspecified security"
        network = f" named {_truncate_description(ssid, 48)}" if ssid else ""
        return f"Ask the device to join a Wi-Fi network{network} using {auth}."
    if payload_type == "SMS":
        target = normalized.split(":", 1)[1].split(":", 1)[0] if ":" in normalized else ""
        recipient = f" to {_truncate_description(target, 48)}" if target else ""
        return f"Open a prefilled text message{recipient}; it should still require review before sending."
    if payload_type == "Email":
        parsed = urlparse(normalized)
        recipient = parsed.path or normalized.replace("mailto:", "", 1)
        target = f" to {_truncate_description(recipient, 48)}" if recipient else ""
        return f"Open a prefilled email{target}; it should still require review before sending."
    if payload_type == "Crypto/payment":
        scheme = normalized.split(":", 1)[0].lower()
        return f"Open a {scheme} wallet or payment request; approval should happen only inside the wallet."
    if payload_type == "Phone":
        return f"Open a call to {_truncate_description(normalized.split(':', 1)[1], 48)}; review the number before dialing."
    if payload_type == "Authentication":
        return "Import a one-time-password secret into an authenticator. Keep the secret private and verify the account."
    if payload_type == "App/deep link":
        scheme = normalized.split(":", 1)[0].lower()
        return f"Hand this {scheme} link to an app, which may perform an app-specific action."
    if payload_type == "Contact card":
        name = _qr_field_value(normalized, "FN") or _qr_field_value(normalized, "N")
        contact = f" for {_truncate_description(name, 48)}" if name else ""
        return f"Offer to add contact details{contact} to the address book."
    if payload_type == "Calendar":
        title = _qr_field_value(normalized, "SUMMARY")
        event = f" named {_truncate_description(title, 48)}" if title else ""
        return f"Offer to add a calendar event{event}."
    if payload_type == "JSON/custom":
        return "Pass structured data to an app or service that understands this QR format."
    return "Display the decoded text payload without launching a standard browser, wallet, or message flow."

def detect_payload(raw_payload):
    payload = raw_payload.strip()
    upper = payload.upper()

    if is_url_like(payload):
        return "URL", "Open website", normalize_url(payload)
    if upper.startswith("WIFI:"):
        return "Wi-Fi", "Join Wi-Fi network", payload
    if "BEGIN:VCARD" in upper:
        return "Contact card", "Import contact", payload
    if upper.startswith(("SMSTO:", "SMS:")):
        return "SMS", "Open prefilled text message", payload
    if upper.startswith("MAILTO:"):
        return "Email", "Open prefilled email", payload
    if upper.startswith(("SOLANA:", "BITCOIN:", "ETHEREUM:", "WC:", "UPI:")):
        return "Crypto/payment", "Open wallet or payment request", payload
    if upper.startswith("TEL:"):
        return "Phone", "Dial phone number", payload
    if upper.startswith("OTPAUTH:"):
        return "Authentication", "Import authenticator secret", payload
    if upper.startswith("INTENT:"):
        return "App/deep link", "Open app intent", payload
    if upper.startswith("BEGIN:VEVENT") or "BEGIN:VCALENDAR" in upper:
        return "Calendar", "Add calendar event", payload

    try:
        json.loads(payload)
        return "JSON/custom", "Run app-specific data flow", payload
    except ValueError:
        pass
    # Unknown URI schemes are actionable: another app may claim them. Treating
    # them as plain text would give an unsupported app action a SAFE verdict.
    if re.match(r"^[a-z][a-z0-9+.-]*:", payload, flags=re.IGNORECASE):
        return "App/deep link", "Open app-specific link", payload
    return "Plain text", "Display text payload", payload

def analyze_non_url_payload(raw_payload):
    payload_type, action, normalized = detect_payload(raw_payload)
    action_description = describe_qr_action(payload_type, normalized)
    embedded_urls = extract_urls(normalized)
    score = 0
    status = "SAFE"
    threat_class = f"{payload_type}: {action}"
    reasons = []

    if payload_type == "Wi-Fi":
        score = 25
        status = "CAUTION"
        if "T:WEP" in normalized.upper() or "T:NOPASS" in normalized.upper():
            score = 45
            threat_class = "Wi-Fi network with weak or open security"
            reasons.append(risk_reason("Weak Wi-Fi security", "medium", "The QR can join a WEP or open network. Confirm the network is trusted before joining."))
        else:
            threat_class = "Wi-Fi join request: review network name before joining"
            reasons.append(risk_reason("Wi-Fi join request", "low", "The QR changes device network state, so the SSID and security type should be reviewed."))
    elif payload_type in ("SMS", "Email"):
        score = 35
        status = "CAUTION"
        threat_class = f"{payload_type} action: review recipient and message before sending"
        reasons.append(risk_reason(f"{payload_type} action", "medium", "The QR can open a prefilled message. Review the recipient and body before sending."))
    elif payload_type == "Contact card":
        score = 20
        status = "CAUTION"
        threat_class = "Contact import: review names, phone numbers, and links before saving"
        reasons.append(risk_reason("Contact import", "low", "The QR can add contact data to your device. Review names, phone numbers, and links."))
    elif payload_type == "Crypto/payment":
        score = 60
        status = "CAUTION"
        threat_class = "Wallet/payment request: verify destination before approving"
        reasons.append(risk_reason("Wallet or payment request", "high", "The QR can launch a crypto wallet or payment flow. Verify the destination before approving."))
    elif payload_type == "Phone":
        score = 40
        status = "CAUTION"
        threat_class = "Phone call request: verify the number before dialing"
        reasons.append(risk_reason("Phone call request", "medium", "The QR can initiate a call, including to a premium-rate or impersonator number."))
    elif payload_type == "Authentication":
        score = 65
        status = "CAUTION"
        threat_class = "Authenticator import: protect the one-time-password secret"
        reasons.append(risk_reason("Authenticator secret", "high", "The QR can import an account secret into an authenticator. Verify the account and do not share this payload."))
    elif payload_type == "App/deep link":
        score = 60
        status = "CAUTION"
        threat_class = "App deep link: app-specific action is not verified"
        reasons.append(risk_reason("App deep link", "high", "This scheme can hand control to another app. SafeScan cannot verify what that app will do."))
    elif payload_type == "Calendar":
        score = 20
        status = "CAUTION"
        threat_class = "Calendar event: review event details before adding"
        reasons.append(risk_reason("Calendar write request", "low", "The QR can add an event to the calendar. Review the organizer, links, and date."))
    elif payload_type == "JSON/custom":
        score = 30
        status = "CAUTION"
        threat_class = "Custom app payload: inspect app-specific action before running"
        reasons.append(risk_reason("Custom app payload", "medium", "The QR contains structured data that another app may interpret."))

    if embedded_urls:
        score = max(score, 45)
        status = "CAUTION"
        threat_class = f"{payload_type} containing embedded URL: inspect destination before action"
        reasons.append(risk_reason("Embedded URL detected", "medium", "The payload contains URL-shaped text inside another QR action; SafeScan did not fetch it."))
        if len(embedded_urls) > MAX_EMBEDDED_URLS:
            score = max(score, 79)
            reasons.append(risk_reason("Embedded link limit", "high", f"Only the first {MAX_EMBEDDED_URLS} URL-shaped values were checked locally."))
        for embedded_url in embedded_urls[:MAX_EMBEDDED_URLS]:
            local_score, local_reason = local_embedded_url_risk(embedded_url)
            score = max(score, local_score)
            reasons.append(local_reason)

    risky_words = ("password", "seed", "recovery", "verify", "login", "wallet", "bank", "urgent")
    if any(word in normalized.lower() for word in risky_words):
        score = max(score, 55)
        status = "CAUTION"
        threat_class = f"{payload_type} includes sensitive or urgency language"
        reasons.append(risk_reason("Sensitive language", "medium", "The payload references wallet, password, login, recovery, or urgency wording."))

    if not reasons:
        reasons.append(risk_reason("No risky payload pattern detected", "low", "SafeScan did not find wallet-drainer, credential, redirect, or suspicious QR action indicators."))

    # Run the ML classifier on non-URL payloads too. The full URL pipeline
    # already does this, but a plain non-URL payload (e.g. "9995", a vCard,
    # a Wi-Fi join) used to skip the model entirely - so a malicious custom
    # payload never got a model opinion. We run it, blend it into the score
    # so the model can raise the verdict, and attach mlRisk so the result
    # page shows what the model thinks. Popular/trusted domains never reach
    # this path (they short-circuit on the allowlist), so the model only
    # surfaces for non-trusted destinations - which is the intent.
    minimum_action_score = 40 if status == "CAUTION" else 0
    score = max(score, minimum_action_score)
    ml_result = classify_qr_with_ml(normalized)
    blended = blend_ml_score(score, ml_result, reasons)
    score = max(blended, minimum_action_score)
    status = status_from_risk(risk_from_score(score))
    ml_signal = ml_signal_from_result(ml_result, label="ML Risk Model", description_prefix="QR payload classifier")
    if ml_signal and ML_SIGNAL_VISIBLE:
        reasons.append(ml_signal)

    return {
        "status": status,
        "score": str(score),
        "threat_class": threat_class,
        "source": "SafeScan Payload Analyzer",
        "normalized": normalized,
        "payload_type": payload_type,
        "action_description": action_description,
        "verificationStatus": "unverified" if payload_type != "Plain text" or embedded_urls else "not_applicable",
        "unverifiedChecks": (["Action in the receiving app"] if payload_type != "Plain text" else []) + (["Embedded links not fetched"] if embedded_urls else []) + (["Embedded URLs beyond local scan limit"] if len(embedded_urls) > MAX_EMBEDDED_URLS else []),
        "reputation": {"provider": "SafeScan Payload Analyzer", "status": "NOT_APPLICABLE", "matches": [], "detail": "Reputation lookup only runs for URL payloads."},
        "reasons": reasons,
        "mlRisk": ml_result
    }

def analyze_url_payload(raw_payload):
    normalized = validate_public_url(raw_payload)
    action_description = describe_qr_action("URL", normalized)
    parsed = urlparse(normalized)
    lower_url = normalized.lower()
    score = 0
    threat_class = "Safe Destination"
    reasons = []

    cached_status = get_cached_result(normalized)
    if cached_status:
        return {
            "status": cached_status,
            "score": "95" if cached_status == "MALICIOUS" else "0",
            "threat_class": "Phishing/Malware Risk" if cached_status == "MALICIOUS" else "Safe Destination",
            "source": "Local Cache",
            "normalized": normalized,
            "payload_type": "URL",
            "action_description": action_description,
            "reputation": {"provider": "Local Cache", "status": cached_status, "matches": [], "detail": "Cached verdict from the last 24 hours."},
            "reasons": [risk_reason("Cached reputation verdict", "high" if cached_status == "MALICIOUS" else "low", "This URL was recently scanned and reused from local cache.")]
        }

    reputation = check_url_reputation(normalized)
    redirect_result = inspect_redirects(normalized)
    status = "MALICIOUS" if reputation["status"] == "MALICIOUS" else "SAFE"

    if parsed.scheme != "https":
        score += 20
        threat_class = "Non-HTTPS destination"
        reasons.append(risk_reason("Non-HTTPS destination", "medium", "The decoded URL does not use HTTPS, which makes spoofing and interception riskier."))
    if parsed.hostname and parsed.hostname.endswith((".top", ".zip", ".click", ".shop")):
        score += 20
        threat_class = "Higher-risk URL destination"
        reasons.append(risk_reason("Higher-risk top-level domain", "medium", "The domain uses a TLD often seen in disposable phishing or scam campaigns."))
    if any(keyword in lower_url for keyword in ("download", ".apk", ".exe", ".dmg", ".pkg", ".zip")):
        score += 45
        threat_class = "Download or installer link: review before opening"
        reasons.append(risk_reason("Download or installer link", "high", "The URL appears to trigger a download or installer path."))
    if any(keyword in lower_url for keyword in ("verify", "login", "password", "wallet", "seed", "recovery")):
        score += 25
        threat_class = "Credential or wallet-themed URL"
        reasons.append(risk_reason("Credential or wallet wording", "high", "The URL contains login, seed, recovery, password, verify, or wallet language."))
    if any(keyword in lower_url for keyword in ("drain", "drainer", "approve", "approval", "permit", "signature", "sign-message", "airdrop", "claim")):
        score += 35
        threat_class = "Wallet drain signature pattern"
        reasons.append(risk_reason("Wallet drain signature pattern", "high", "The URL uses claim, approve, signature, permit, or drainer language often seen in wallet-draining flows."))
    if redirect_result["count"] > 0:
        score += min(30, redirect_result["count"] * 15)
        threat_class = "Redirecting destination"
        reasons.append(risk_reason("Redirects detected", "medium", f"The URL redirects {redirect_result['count']} time(s) before landing on {redirect_result['final_url']}."))
    elif redirect_result["status"] == "ERROR":
        reasons.append(risk_reason("Redirect inspection unavailable", "low", redirect_result["detail"]))

    if status == "MALICIOUS":
        score = 95
        threat_class = "Phishing/Malware Risk"
        reasons.insert(0, risk_reason("Google Safe Browsing match", "high", "Live reputation lookup returned a known unsafe threat match."))
    elif score >= 45:
        status = "CAUTION"
    else:
        score = 0

    if reputation["status"] == "CLEAR":
        reasons.append(risk_reason("Reputation lookup clear", "low", "Google Safe Browsing did not return a known unsafe match for this URL."))
    elif reputation["status"] in ("UNCONFIGURED", "ERROR"):
        reasons.append(risk_reason("Reputation lookup unavailable", "low", reputation["detail"]))
    if not reasons:
        reasons.append(risk_reason("No suspicious URL pattern detected", "low", "SafeScan did not find redirect, wallet-drainer, credential, or high-risk URL indicators."))

    save_to_cache(normalized, status)
    return {
        "status": status,
        "score": str(min(score, 95)),
        "threat_class": threat_class,
        "source": "SafeScan Engine",
        "normalized": normalized,
        "payload_type": "URL",
        "action_description": action_description,
        "reputation": reputation,
        "reasons": reasons
    }

def analyze_qr_payload(raw_payload):
    """Analyse a decoded QR payload of any type (sync entry point).

    Detects what kind of payload it is and dispatches to the URL analyzer or
    the non-URL analyzer (wifi, vcard, crypto address, plain text, ...),
    returning a template-ready analysis dict.
    """
    payload_type, _, normalized = detect_payload(raw_payload)
    if payload_type == "URL":
        return analyze_url_payload(normalized)
    return analyze_non_url_payload(normalized)

def pipeline_response_to_template_analysis(pipeline_response):
    overall_risk = pipeline_response["overallRisk"]
    signals = pipeline_response.get("signals", [])
    first_high = next((item for item in signals if item["severity"] == "high"), None)
    first_signal = first_high or (signals[0] if signals else None)
    return {
        "status": status_from_risk(overall_risk),
        "score": str(pipeline_response["confidenceScore"]),
        "threat_class": pipeline_response.get("threatType") or threat_type_for_analysis(overall_risk, signals, pipeline_response.get("mlRisk")) or (first_signal["check"] if first_signal else "SafeScan Risk Engine"),
        "source": "SafeScan Core Risk Engine",
        "normalized": pipeline_response["url"],
        "payload_type": "URL",
        "action_description": describe_qr_action("URL", pipeline_response["url"]),
        "overallRisk": overall_risk,
        "verdict": pipeline_response["verdict"],
        "reputation": {"provider": "SafeScan Core Risk Engine", "status": overall_risk.upper(), "matches": [], "detail": pipeline_response["verdict"]},
        "reasons": signals,
        "virusTotal": pipeline_response.get("virusTotal"),
        "domainAge": pipeline_response.get("domainAge"),
        "mlRisk": pipeline_response.get("mlRisk"),
        "ruleScore": pipeline_response.get("ruleScore"),
        "verificationStatus": pipeline_response.get("verificationStatus"),
        "unverifiedChecks": pipeline_response.get("unverifiedChecks", []),
        # Present when the allowlist/first-party fast path produced the verdict;
        # the result modal uses it to show the "verified instantly" chip.
        "fastPath": pipeline_response.get("fastPath")
    }

async def analyze_embedded_url_payload(raw_payload, embedded_url=None, qr_image=None):
    """Legacy async entrypoint for private QR actions.

    Embedded URL-shaped values are examined only by local heuristics. Their
    fields can contain secrets, so this helper must never fetch them or send
    them to URL reputation providers.
    """
    result = analyze_non_url_payload(raw_payload)
    result["normalized"] = raw_payload
    result["overallRisk"] = risk_from_score(clamp_score(result["score"]))
    result["analyzedUrls"] = []
    result["verdict"] = "This QR action and any embedded URL-shaped values were assessed locally. No embedded destination was fetched or verified."
    return result
