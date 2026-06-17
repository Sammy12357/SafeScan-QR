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
from .config import ANTHROPIC_API_KEY
from .config import ML_SIGNAL_VISIBLE
from .config import MOCK_MODE
from .config import OPENAI_API_KEY
from .heuristics import check_crypto_pattern_signals
from .heuristics import check_domain_intelligence
from .qr_image import blend_ml_score
from .qr_image import classify_qr_with_ml
from .qr_image import ml_signal_from_result
from .qr_image import verdict_with_ml
from .redirects import trace_redirect_chain
from .reputation import google_reputation_signal
from .reputation import mock_analysis_response
from .reputation import threat_type_for_analysis
from .scoring import clamp_score
from .scoring import risk_from_score
from .scoring import score_from_signals
from .scoring import severity_rank
from .scoring import signal
from .scoring import virustotal_breakdown_signal
from .scoring import virustotal_lookup_result
from .security import validate_public_url

# =============================================================================
# AI VERDICT & FULL ANALYSIS PIPELINE
# analyze_full_pipeline() orchestrates all of the above checks (mostly in
# parallel) and blends them into one verdict — this is the product's core.
# =============================================================================
def generate_ai_verdict(signals):
    score = score_from_signals(signals)
    overall_risk = risk_from_score(score)
    high_checks = [item["check"] for item in signals if item["severity"] == "high"]
    medium_checks = [item["check"] for item in signals if item["severity"] == "medium"]

    if high_checks:
        verdict = f"This QR code shows high-risk indicators in {', '.join(high_checks[:3])}. Do not continue unless you can independently verify the destination and sender."
    elif medium_checks:
        verdict = f"This QR code looks suspicious because {', '.join(medium_checks[:3])} need review. Continue only after confirming the domain, redirect path, and wallet action."
    else:
        verdict = "SafeScan did not find strong phishing or wallet-drain indicators in this QR payload. Still verify the destination before connecting a wallet or sending funds."

    fallback = {"overallRisk": overall_risk, "confidenceScore": score, "verdict": verdict}
    analyst_prompt = (
        "You are a QR security analyst. Review these SafeScan signal objects and return JSON only with "
        "overallRisk as safe, suspicious, or high; confidenceScore from 0-100; and verdict as a two-sentence "
        "plain-English explanation. Weight high severity at 40 points each capped at 80, medium at 15, low at 5, "
        "and push new-domain + redirect + wallet-pattern combinations to 90+.\n\n"
        f"Signals JSON:\n{json.dumps(signals)}"
    )

    try:
        if ANTHROPIC_API_KEY:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
                    "max_tokens": 300,
                    "system": "Return structured JSON only. Do not include markdown.",
                    "messages": [{"role": "user", "content": analyst_prompt}]
                },
                timeout=10
            )
            response.raise_for_status()
            content = response.json()["content"][0]["text"]
            return json.loads(content)
        if OPENAI_API_KEY:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "content-type": "application/json"},
                json={
                    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": "You are a QR security analyst. Return structured JSON only."},
                        {"role": "user", "content": analyst_prompt}
                    ]
                },
                timeout=10
            )
            response.raise_for_status()
            return json.loads(response.json()["choices"][0]["message"]["content"])
    except (requests.RequestException, KeyError, IndexError, ValueError, json.JSONDecodeError):
        return fallback

    return fallback

async def analyze_full_pipeline(target_url, qr_image=None):
    """Run the complete risk analysis for a URL and return the verdict dict.

    This is the product's core. Flow:
      1. Validate/normalise the URL (also blocks SSRF to private hosts).
      2. Fast path: if the domain is on the Tranco popular-site allowlist and
         passes a structural safety screen, only run Google Safe Browsing and
         return ``safe`` immediately (skips the expensive stages).
      3. Otherwise trace the redirect chain so every downstream check runs
         against the *final* destination, then run the rule signals, ML
         classifier, VirusTotal/GSB reputation, domain-age and crypto/typosquat
         heuristics (largely in parallel).
      4. Blend the rule score with the ML score, derive the overall risk band,
         status and threat type, and return a single result dict consumed by
         both the HTML result page and the JSON API.

    ``qr_image`` (optional) lets the ML image classifier weigh in when the URL
    text alone is borderline.
    """
    normalized = validate_public_url(target_url)
    if MOCK_MODE:
        return mock_analysis_response(normalized)

    if is_first_party(normalized):
        # The URL points at this SafeScan deployment itself (generator page,
        # shared scan results, referral links). The ML pipeline misfires on
        # onrender.com because it's multi-tenant hosting, and asking outside
        # reputation services about our own domain is circular - so first-party
        # links get a deterministic SAFE verdict. Exact-hostname matching plus
        # the absence of any open-redirect endpoint in the app (safe_next_url
        # only allows same-site relative paths) makes this safe to trust.
        first_party_host = urlparse(normalized).hostname or ""
        first_party_signal = signal(
            "Official SafeScan link",
            f"{first_party_host} is this SafeScan deployment",
            "low",
            "This URL points at SafeScan's own domain. First-party pages are served by this deployment and can't be tampered with by third parties, so the ML and reputation pipeline was skipped in favor of a deterministic safe verdict.",
            True,
        )
        first_party_score = clamp_score(2)
        return {
            "url": normalized,
            "overallRisk": "safe",
            "confidenceScore": first_party_score,
            "ruleScore": first_party_score,
            "mlRisk": {"enabled": False, "reason": "first-party short-circuit"},
            "threatType": "Official SafeScan page",
            "verdict": "safe",
            "signals": [first_party_signal],
            "virusTotal": None,
            "domainAge": None,
            "redirectChain": [],
            "scannedAt": datetime.utcnow().isoformat() + "Z",
            "fastPath": {"hit": True, "reason": "first_party"},
        }

    fast_path_ok, fast_path_reason = should_short_circuit(normalized)
    if fast_path_ok:
        # Run only the cheap reputation check before declaring safe. If Google
        # Safe Browsing flags the URL (compromised popular site, abused open
        # redirect that slipped past the screen, etc.) we fall through to the
        # full pipeline for a real verdict.
        gsb_signal = await asyncio.to_thread(google_reputation_signal, normalized)
        if gsb_signal.get("passed", False) and gsb_signal.get("severity") == "low":
            vt_result = await asyncio.to_thread(virustotal_lookup_result, normalized)
            allowlist_signal = signal(
                "Allowlist match",
                f"{allowlist_registrable_domain(normalized.split('//', 1)[-1].split('/', 1)[0])} on Tranco popularity allowlist",
                "low",
                "SafeScan recognized this destination as a widely-trafficked, popular domain that passed structural safety screening (HTTPS, no homograph chars, no shorteners, no redirect parameters). The full ML/domain pipeline was skipped because no expensive analysis is warranted; Google Safe Browsing and VirusTotal were still consulted for reputation context.",
                True,
            )
            fast_signals = sorted([allowlist_signal, gsb_signal, virustotal_breakdown_signal(vt_result)], key=severity_rank)
            fast_score = clamp_score(8)
            return {
                "url": normalized,
                "overallRisk": "safe",
                "confidenceScore": fast_score,
                "ruleScore": fast_score,
                "mlRisk": {"enabled": False, "reason": "allowlist short-circuit"},
                "threatType": "Benign popular destination",
                "verdict": "safe",
                "signals": fast_signals,
                "virusTotal": vt_result,
                "domainAge": None,
                "redirectChain": [],
                "scannedAt": datetime.utcnow().isoformat() + "Z",
                "fastPath": {"hit": True, "reason": "tranco_allowlist"},
            }
        # GSB returned a non-trivial signal - fall through to full pipeline.

    # Resolve the redirect chain first so reputation/domain/crypto checks run
    # against the actual destination, not the (possibly shortened) QR
    # payload URL. A bit.ly link that redirects to a wallet-drain page is
    # otherwise checked against bit.ly's clean reputation and brand-new
    # crypto-drain query params on the final hop are never inspected.
    redirect_result = await asyncio.to_thread(trace_redirect_chain, normalized)
    chain = redirect_result.get("redirectChain") or []
    final_url = chain[-1]["url"] if chain else normalized

    vt_task = asyncio.to_thread(virustotal_lookup_result, final_url)
    domain_task = asyncio.to_thread(check_domain_intelligence, final_url)
    reputation_task = asyncio.to_thread(check_reputation_signals, final_url)
    crypto_task = asyncio.to_thread(check_crypto_pattern_signals, final_url)
    input_source = "uploaded_qr" if qr_image is not None else "generated_qr"
    ml_task = asyncio.to_thread(classify_qr_with_ml, normalized, qr_image, input_source)
    domain_result, reputation_signals, crypto_signals, ml_result, vt_result = await asyncio.gather(
        domain_task, reputation_task, crypto_task, ml_task, vt_task
    )

    signals = []
    signals.extend(domain_result if isinstance(domain_result, list) else [domain_result])
    domain_age = next((item.get("domainAge") for item in signals if item.get("domainAge")), None)
    signals.append(redirect_result["signal"])
    signals.extend(reputation_signals)
    signals.append(virustotal_breakdown_signal(vt_result))
    signals.extend(crypto_signals)
    # ML signal is kept around so the score blend + audit trail can use it,
    # but it's NOT appended to the user-visible signals list by default —
    # exposing classifier internals ("url_classifier.joblib 98.5% malicious")
    # is confusing UX, especially when the trained model misfires on safe
    # consumer domains. Flip SAFESCAN_ML_SIGNAL_VISIBLE=true to show it
    # again for debugging.
    ml_signal = ml_signal_from_result(ml_result, label="ML Risk Model", description_prefix="EfficientNet QR classifier")
    if ml_signal and ML_SIGNAL_VISIBLE:
        signals.append(ml_signal)
    signals = sorted(signals, key=severity_rank)
    ai_verdict = generate_ai_verdict(signals)
    final_score = blend_ml_score(ai_verdict["confidenceScore"], ml_result, signals)
    overall_risk = risk_from_score(final_score)

    return {
        "url": normalized,
        "overallRisk": overall_risk,
        "confidenceScore": final_score,
        "ruleScore": clamp_score(ai_verdict["confidenceScore"]),
        "mlRisk": ml_result,
        "threatType": threat_type_for_analysis(overall_risk, signals, ml_result),
        "verdict": verdict_with_ml(ai_verdict["verdict"], final_score, ml_result, signals),
        "signals": signals,
        "virusTotal": vt_result,
        "domainAge": domain_age,
        "redirectChain": redirect_result.get("redirectChain", []),
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_reputation_signals(target_url):
    return [google_reputation_signal(target_url)]

def is_url_like(value):
    return bool(re.match(r"^https?://", value, re.IGNORECASE) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", value, re.IGNORECASE))


def decimal_text(value, places=9):
    quantized = value.quantize(Decimal(1).scaleb(-places))
    return format(quantized.normalize(), "f")

