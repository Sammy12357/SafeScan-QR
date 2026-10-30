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

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party, safety_screen
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
from .phish_feed import phishtank_signal
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
    """Return a rule-based verdict; untrusted prose cannot set the risk score."""
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

    return {"overallRisk": overall_risk, "confidenceScore": score, "verdict": verdict}


def verification_coverage(signals):
    """Identify checks that could not return a definitive result."""
    unverified = list(dict.fromkeys(
        item["check"] for item in signals if item.get("verified") is False
    ))
    return ("incomplete" if unverified else "complete"), unverified


def known_malicious_reputation(signals):
    return any(
        item.get("check") in ("Google Safe Browsing", "Google Web Risk", "PhishTank", "VirusTotal Reputation")
        and item.get("severity") == "high"
        and item.get("verified") is not False
        and item.get("passed") is False
        for item in signals
    )

async def analyze_full_pipeline(target_url, qr_image=None):
    """Run the complete risk analysis for a URL and return the verdict dict.

    This is the product's core. Flow:
      1. Validate/normalise the URL (also blocks SSRF to private hosts).
      2. Fast path: for official or popular domains that pass a structural
         screen, require reputation and redirect checks before returning safe.
      3. Otherwise trace the redirect chain so every downstream check runs
         against the *final* destination, then run the rule signals, ML
         classifier, Web Risk/PhishTank reputation, domain-age and crypto/typosquat
         heuristics (largely in parallel).
      4. Blend the rule score with the ML score, derive the overall risk band,
         status and threat type, and return a single result dict consumed by
         both the HTML result page and the JSON API.

    ``qr_image`` (optional) lets the ML image classifier weigh in when the URL
    text alone is borderline.
    """
    normalized = validate_public_url(target_url)
    if MOCK_MODE:
        result = mock_analysis_response(normalized)
        result["verificationStatus"] = "incomplete"
        result["unverifiedChecks"] = ["Live reputation and redirect checks"]
        return result

    prechecked_redirect = None
    is_official = is_first_party(normalized)
    fast_path_ok = is_official and safety_screen(normalized)[0]
    if not fast_path_ok:
        fast_path_ok, _ = should_short_circuit(normalized)
    if fast_path_ok:
        google_signal, phish_signal, vt_result, fast_redirect = await asyncio.gather(
            asyncio.to_thread(google_reputation_signal, normalized),
            asyncio.to_thread(phishtank_signal, normalized),
            asyncio.to_thread(virustotal_lookup_result, normalized),
            asyncio.to_thread(trace_redirect_chain, normalized),
        )
        if is_official:
            allowlist_signal = signal(
                "Official SafeScan link",
                f"{urlparse(normalized).hostname} is a configured SafeScan host",
                "low",
                "This URL uses a configured SafeScan host and passed structural screening. Reputation and redirect checks were also required.",
                True,
            )
        else:
            allowlist_signal = signal(
                "Allowlist match",
                f"{allowlist_registrable_domain(normalized.split('//', 1)[-1].split('/', 1)[0])} on Tranco popularity allowlist",
                "low",
                "This popular HTTPS destination passed structural safety screening. Reputation and redirect checks were also required.",
                True,
            )
        vt_finding = virustotal_breakdown_signal(vt_result)
        optional_checks = [] if vt_finding.get("verified") is True else [{
            "check": "VirusTotal Reputation", "status": vt_result.get("mode", "unavailable"),
            "detail": vt_result.get("statusMessage", "Optional enrichment unavailable."),
        }]
        fast_signals = sorted(
            [allowlist_signal, google_signal, phish_signal, fast_redirect["signal"],
             *([vt_finding] if vt_finding.get("verified") is True else [])],
            key=severity_rank,
        )
        verification_status, unverified_checks = verification_coverage(fast_signals)
        # A confirmed reputation hit takes precedence even if another provider
        # is down. Never let the popularity allowlist overwrite it.
        dangerous_redirect = fast_redirect["signal"].get("severity") == "high"
        known_bad = known_malicious_reputation(fast_signals)
        has_redirect = len(fast_redirect.get("redirectChain") or []) > 1
        if known_bad:
            fast_risk, fast_score, fast_type = "high", 95, "Known malicious destination"
            fast_verdict = "A reputation provider identified this destination as unsafe. Do not open it."
        elif dangerous_redirect:
            fast_risk, fast_score, fast_type = "high", 80, "High-risk redirect path"
            fast_verdict = "This URL has a high-risk redirect pattern or a blocked redirect target. Review the destination before continuing."
        elif verification_status == "incomplete":
            fast_risk, fast_score, fast_type = "suspicious", max(40, score_from_signals(fast_signals)), "Unverified destination"
            fast_verdict = "SafeScan could not complete every required check for this destination. Verify it independently before continuing."
        else:
            fast_risk, fast_score, fast_type = "safe", 8, "Official SafeScan destination" if is_official else "Benign popular destination"
            fast_verdict = "No known unsafe match or redirect was found for this destination."
        # A redirect needs destination-specific analysis; the popularity of
        # the first hop says nothing about its landing page.
        needs_landing_page_analysis = has_redirect and not known_bad
        if not needs_landing_page_analysis:
            return {
                "url": normalized,
                "overallRisk": fast_risk,
                "confidenceScore": clamp_score(fast_score),
                "ruleScore": clamp_score(fast_score),
                "mlRisk": {"enabled": False, "reason": "first-party short-circuit" if is_official else "allowlist short-circuit"},
                "threatType": fast_type,
                "verdict": fast_verdict,
                "signals": fast_signals,
                "virusTotal": vt_result,
                "domainAge": None,
                "redirectChain": fast_redirect.get("redirectChain", []),
                "verificationStatus": verification_status,
                "unverifiedChecks": unverified_checks,
                "optionalChecks": optional_checks,
                "scannedAt": datetime.utcnow().isoformat() + "Z",
                "fastPath": {"hit": True, "reason": "first_party" if is_official else "tranco_allowlist"},
            }
        prechecked_redirect = fast_redirect

    # Resolve the redirect chain first so reputation/domain/crypto checks run
    # against the actual destination, not the (possibly shortened) QR
    # payload URL. A bit.ly link that redirects to a wallet-drain page is
    # otherwise checked against bit.ly's clean reputation and brand-new
    # crypto-drain query params on the final hop are never inspected.
    redirect_result = prechecked_redirect or await asyncio.to_thread(trace_redirect_chain, normalized)
    chain = redirect_result.get("redirectChain") or []
    final_url = chain[-1]["url"] if chain else normalized

    # Check each distinct hop, including the original QR URL. Limit lookups
    # for unusually long chains; skipped hops make verification incomplete.
    hop_urls = list(dict.fromkeys([normalized, *(item["url"] for item in chain)]))
    skipped_hops = len(hop_urls) > 6
    if skipped_hops:
        hop_urls = hop_urls[:3] + hop_urls[-3:]
    reputation_slots = asyncio.Semaphore(3)

    async def inspect_hop(url):
        async with reputation_slots:
            return await asyncio.gather(
                asyncio.to_thread(check_reputation_signals, url),
                asyncio.to_thread(virustotal_lookup_result, url),
            )

    hop_task = asyncio.gather(*(inspect_hop(url) for url in hop_urls))
    domain_task = asyncio.to_thread(check_domain_intelligence, final_url)
    crypto_task = asyncio.to_thread(check_crypto_pattern_signals, final_url)
    input_source = "uploaded_qr" if qr_image is not None else "generated_qr"
    ml_task = (
        asyncio.sleep(0, result={"enabled": False, "reason": "first-party host"})
        if is_official else asyncio.to_thread(classify_qr_with_ml, normalized, qr_image, input_source)
    )
    domain_result, crypto_signals, ml_result, hop_results = await asyncio.gather(
        domain_task, crypto_task, ml_task, hop_task
    )
    required_hop_signals = []
    for checked_url, (reputation_signals, _) in zip(hop_urls, hop_results):
        for item in reputation_signals:
            finding = dict(item)
            finding["checkedUrl"] = checked_url
            required_hop_signals.append(finding)
    if not required_hop_signals:
        finding = signal("Google Reputation", "Unverified (no result)", "medium", "The reputation provider returned no result.", False)
        finding["verified"] = False
        required_hop_signals.append(finding)
    vt_hop_results = [result for _, result in hop_results]
    vt_hop_signals = [virustotal_breakdown_signal(result) for result in vt_hop_results]
    for checked_url, finding in zip(hop_urls, vt_hop_signals):
        finding["checkedUrl"] = checked_url

    def most_concerning_index(findings):
        for index, finding in enumerate(findings):
            if finding.get("severity") == "high" and finding.get("passed") is False:
                return index
        for index, finding in enumerate(findings):
            if finding.get("verified") is False:
                return index
        return len(findings) - 1

    google_hop_signals = [item for item in required_hop_signals if item["check"] != "PhishTank"]
    phish_hop_signals = [item for item in required_hop_signals if item["check"] == "PhishTank"]
    google_signal = google_hop_signals[most_concerning_index(google_hop_signals)] if google_hop_signals else None
    phish_signal = phish_hop_signals[most_concerning_index(phish_hop_signals)] if phish_hop_signals else None
    vt_index = most_concerning_index(vt_hop_signals)
    vt_signal = vt_hop_signals[vt_index]
    vt_result = vt_hop_results[vt_index]
    _, hop_unverified_checks = verification_coverage(required_hop_signals)
    optional_checks = [
        {"check": "VirusTotal Reputation", "status": result.get("mode", "unavailable"),
         "detail": result.get("statusMessage", "Optional enrichment unavailable."), "checkedUrl": url}
        for url, result, finding in zip(hop_urls, vt_hop_results, vt_hop_signals)
        if finding.get("verified") is not True
    ]

    signals = []
    signals.extend(domain_result if isinstance(domain_result, list) else [domain_result])
    domain_age = next((item.get("domainAge") for item in signals if item.get("domainAge")), None)
    signals.append(redirect_result["signal"])
    if google_signal:
        signals.append(google_signal)
    if phish_signal:
        signals.append(phish_signal)
    if vt_signal.get("verified") is True:
        signals.append(vt_signal)
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
    rule_score = score_from_signals(signals)
    final_score = blend_ml_score(rule_score, ml_result, signals)
    verification_status, unverified_checks = verification_coverage(signals)
    unverified_checks = list(dict.fromkeys([*hop_unverified_checks, *unverified_checks]))
    if skipped_hops:
        unverified_checks.append("Additional redirect hops")
    verification_status = "incomplete" if unverified_checks else "complete"
    if known_malicious_reputation(signals):
        final_score = max(final_score, 85)
    if redirect_result["signal"].get("severity") == "high":
        final_score = max(final_score, 80)
    if verification_status == "incomplete":
        final_score = max(final_score, 40)
    overall_risk = risk_from_score(final_score)

    return {
        "url": normalized,
        "overallRisk": overall_risk,
        "confidenceScore": final_score,
        "ruleScore": clamp_score(rule_score),
        "mlRisk": ml_result,
        "threatType": threat_type_for_analysis(overall_risk, signals, ml_result),
        "verdict": verdict_with_ml(ai_verdict["verdict"], final_score, ml_result, signals),
        "signals": signals,
        "virusTotal": vt_result,
        "domainAge": domain_age,
        "redirectChain": redirect_result.get("redirectChain", []),
        "verificationStatus": verification_status,
        "unverifiedChecks": unverified_checks,
        "optionalChecks": optional_checks,
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_reputation_signals(target_url):
    return [google_reputation_signal(target_url), phishtank_signal(target_url)]

def is_url_like(value):
    return bool(re.match(r"^https?://", value, re.IGNORECASE) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", value, re.IGNORECASE))


def decimal_text(value, places=9):
    quantized = value.quantize(Decimal(1).scaleb(-places))
    return format(quantized.normalize(), "f")

