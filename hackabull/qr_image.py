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
from .config import ML_AGGREGATE_WEIGHT
from .config import ML_MODEL_ENABLED
from .config import ML_MODEL_PATH
from .history import ensure_ml_model_available
from .scoring import clamp_score
from .scoring import risk_from_score
from .scoring import signal

# =============================================================================
# QR IMAGE GENERATION & ML CLASSIFICATION
# =============================================================================
def qr_image_from_payload(payload):
    import qrcode
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=2, box_size=4)
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")

# Cached geometry for the SafeScan logo mark, parsed once from the brand SVG
# so the generated-QR badge stays in sync with static/safescan-logo.svg
# without re-reading the file on every request.
_SAFESCAN_LOGO_GEOMETRY = None

def _safescan_logo_geometry():
    """Parse static/safescan-logo.svg into (bg_fill, bg_radius, tiles).

    `tiles` is a list of (x, y, w, h, rx, fill) in the SVG's 512x512 space.
    Returns None if the asset can't be read or parsed, so callers can fall
    back to a plain badge instead of failing the whole request.
    """
    global _SAFESCAN_LOGO_GEOMETRY
    if _SAFESCAN_LOGO_GEOMETRY is not None:
        return _SAFESCAN_LOGO_GEOMETRY or None
    try:
        # Static assets live beside the hackabull package at the repository
        # root.  Using ``hackabull/static`` here made the package split fall
        # back to the legacy check-mark badge on every generated QR.
        svg_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "static",
            "safescan-logo.svg",
        )
        root = ElementTree.parse(svg_path).getroot()
        bg_fill, bg_radius, tiles = "#000307", 82.0, []
        for el in root.iter():
            if not el.tag.endswith("rect"):
                continue
            x = float(el.get("x", 0)); y = float(el.get("y", 0))
            w = float(el.get("width", 0)); h = float(el.get("height", 0))
            rx = float(el.get("rx", 0)); fill = el.get("fill", "#72ffd4")
            # The full-canvas rect is the rounded background, not a tile.
            if w >= 512 and h >= 512:
                bg_fill, bg_radius = fill, rx
            else:
                tiles.append((x, y, w, h, rx, fill))
        # Cache the result (empty tuple as a "parsed but unusable" sentinel).
        _SAFESCAN_LOGO_GEOMETRY = (bg_fill, bg_radius, tiles) if tiles else ()
    except Exception:
        _SAFESCAN_LOGO_GEOMETRY = ()
    return _SAFESCAN_LOGO_GEOMETRY or None

def render_safescan_logo(size):
    """Render the SafeScan logo mark as an RGBA image `size`x`size` px.

    Returns None if the brand geometry isn't available.
    """
    from PIL import Image, ImageDraw
    geometry = _safescan_logo_geometry()
    if not geometry:
        return None
    bg_fill, bg_radius, tiles = geometry
    scale = size / 512.0
    logo = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(logo)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=max(1, int(bg_radius * scale)), fill=bg_fill)
    for x, y, w, h, rx, fill in tiles:
        draw.rounded_rectangle(
            [x * scale, y * scale, (x + w) * scale - 1, (y + h) * scale - 1],
            radius=max(1, int(rx * scale)),
            fill=fill,
        )
    return logo

def classify_qr_with_ml(payload, image=None, input_source="generated_qr"):
    """Hybrid ML classification with calibration, cache, and feature bonus.

    Routes the decoded URL through the char-ngram URL classifier first
    (notebook reported 99% accuracy, F1-optimal threshold = 0.32). Falls
    back to the EfficientNet CNN only when the URL classifier artifact
    isn't deployed. Wraps the raw classifier output with:
      - SQLite-backed prediction cache keyed on URL (1hr TTL by default)
      - Calibrated decision bands (benign / uncertain / suspicious / mal)
      - Hand-crafted lexical bonus the char-ngram model can't see
      - Uncertain-band suppression: signal is hidden when probability
        lands in [UNCERTAIN_LOWER, UNCERTAIN_UPPER] so it can't pollute
        the score blend with low-confidence noise.

    See safescan_model_calibration.py for tuning knobs.
    """
    if not ML_MODEL_ENABLED:
        return {"enabled": False, "reason": "disabled"}

    # Cache hit short-circuits the entire ML stack and any image rendering.
    cached = sm_calibration.cache_get(payload) if payload else None
    if cached is not None:
        cached["cacheHit"] = True
        return cached

    generated_image = None
    try:
        ensure_ml_model_available()
        import ml_model_final as _ml_mod

        result = _ml_mod.predict_url(payload) if payload else None
        if result is not None:
            source_input = "decoded_url"
            model_name = os.path.basename(os.getenv(
                "SAFESCAN_URL_CLASSIFIER_PATH",
                os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib"),
            ))
            # If the URL classifier is in the uncertain band, ask the CNN
            # too and blend the two probabilities. The CNN's visual
            # fingerprint occasionally breaks ties the char-ngram model
            # can't, and it costs us nothing on clearly-benign / clearly-
            # malicious URLs because we skip the CNN entirely there.
            url_mal_pct = float(result.get("malicious_prob", 0.0))
            in_uncertain = (
                sm_calibration.UNCERTAIN_LOWER * 100.0
                <= url_mal_pct
                < sm_calibration.UNCERTAIN_UPPER * 100.0
            )
            if in_uncertain:
                try:
                    generated_image = qr_image_from_payload(payload)
                    cnn_result = _ml_mod.predict_image(generated_image)
                    result = _ml_mod.blend_url_and_cnn(result, cnn_result)
                    source_input = "decoded_url+cnn"
                except Exception:
                    # Blend is best-effort; keep the URL-only verdict.
                    pass
        else:
            # CNN fallback - canonical rendering of the decoded URL so the
            # score depends on the URL, not on how the QR was photographed.
            generated_image = qr_image_from_payload(payload)
            result = _ml_mod.predict_image(generated_image)
            source_input = "generated_qr"
            model_name = os.path.basename(ML_MODEL_PATH)

        raw_mal_prob = float(result["malicious_prob"]) / 100.0
        bonus, bonus_reasons = sm_calibration.lexical_feature_bonus(payload)
        adjusted_prob = max(0.0, min(1.0, raw_mal_prob + bonus))
        decision = sm_calibration.interpret_probability(adjusted_prob)

        payload_obj = {
            "enabled": True,
            "trustSignal": decision.trust_signal,
            "model": model_name,
            "modelLabel": "URL pattern model" if source_input == "decoded_url" else "QR image model",
            "source": result.get("source"),
            "inputSource": source_input,
            "score": round(adjusted_prob * 100.0, 1),
            "label": decision.label,
            "bucket": decision.bucket,
            "severity": decision.severity,
            "benignProbability": round(1.0 - adjusted_prob, 4),
            "maliciousProbability": round(adjusted_prob, 4),
            "rawMaliciousProbability": round(raw_mal_prob, 4),
            "lexicalBonus": round(bonus, 4),
            "lexicalReasons": bonus_reasons,
            "raw": [round(1.0 - adjusted_prob, 6), round(adjusted_prob, 6)],
            "cacheHit": False,
        }
        if payload:
            sm_calibration.cache_put(payload, payload_obj)
        return payload_obj
    except Exception as exc:
        return {"enabled": False, "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        if generated_image is not None:
            generated_image.close()

def ml_signal_from_result(ml_result, label="ML Risk Model", description_prefix="CNN QR classifier"):
    if not ml_result or not ml_result.get("enabled"):
        return None
    # Suppress the ML signal entirely when calibration marked it uncertain;
    # forcing a binary call on a ~50/50 score only pollutes the score blend.
    if ml_result.get("trustSignal") is False:
        return None
    score_raw = float(ml_result["score"])
    severity = ml_result.get("severity") or (
        "high" if score_raw >= 80 else ("medium" if score_raw >= 40 else "low")
    )
    mal_pct = round(ml_result["maliciousProbability"] * 100, 1)
    safe_pct = round(ml_result["benignProbability"] * 100, 1)
    description = f"{description_prefix}: {safe_pct}% safe, {mal_pct}% malicious."
    reasons = ml_result.get("lexicalReasons") or []
    if reasons:
        description += f" Lexical bonus applied: {', '.join(reasons[:3])}."
    bucket = ml_result.get("bucket")
    passed = bucket == "benign" if bucket else score_raw < 40
    model_signal = signal(label, f"{round(score_raw, 1)}/100 ML probability", severity, description, passed)
    model_signal["distribution"] = {
        "benign": ml_result["benignProbability"],
        "malicious": ml_result["maliciousProbability"]
    }
    model_signal["model"] = ml_result.get("model")
    model_signal["bucket"] = bucket
    return model_signal

def blend_ml_score(rule_score, ml_results, signals):
    """Weighted blend of the rule score and the available ML score(s).

    Rule signals (domain age, redirect chain, reputation, crypto patterns,
    VirusTotal, Google Safe Browsing) are the source of truth and account
    for `1 - ML_AGGREGATE_WEIGHT` of the final score (default 80%). The
    enabled ML models share the remaining `ML_AGGREGATE_WEIGHT` equally
    (default 20%, averaged across enabled models). With no enabled ML
    models, the rule score is returned unchanged.

    This is intentionally conservative: a misfiring URL classifier that
    labels youtube.com at 98.5% malicious moves the final score by at most
    ~20 points instead of dragging it from "safe" to "high" on its own.
    """
    rule_score = clamp_score(rule_score)
    if isinstance(ml_results, dict) or ml_results is None:
        ml_results = [ml_results]

    enabled_scores = [
        float(r["score"]) for r in ml_results if r and r.get("enabled")
    ]
    if not enabled_scores:
        return clamp_score(rule_score)

    ml_weight = ML_AGGREGATE_WEIGHT
    rule_weight = 1.0 - ml_weight
    ml_mean = sum(enabled_scores) / len(enabled_scores)
    blended = (rule_weight * float(rule_score)) + (ml_weight * ml_mean)

    ml_signal_names = {"ML Risk Model", "ML Risk Model (EfficientNet)"}
    non_ml_high = any(
        item.get("severity") == "high" and item.get("check") not in ml_signal_names
        for item in signals
    )
    # When deterministic rule signals fire "high" (e.g. blocklist hit, VT
    # detection), preserve the high-risk floor — ML's confidence shouldn't
    # talk us out of a known-bad signal. But never the other way around:
    # ML alone cannot push the score into the danger band.
    ml_says_benign = max(enabled_scores) < 40
    if non_ml_high and blended < 75 and not ml_says_benign:
        blended = 75.0
    # If every ML input is confidently benign AND no rule signal flagged
    # high-risk, allow the score to drift slightly below the rule score
    # to reward consensus — but cap how far it can drop.
    if not non_ml_high and max(enabled_scores) <= 15:
        blended = min(blended, max(float(rule_score), 34.0))
    return clamp_score(blended)

def verdict_with_ml(base_verdict, final_score, ml_results, signals):
    """Compose the user-facing verdict text.

    ML inputs are intentionally NOT mentioned in the user-facing copy — the
    classifier names ("url_classifier.joblib") and raw probabilities are
    confusing for end users and risk eroding trust when the model misfires.
    ML's contribution lives inside `final_score` already via blend_ml_score,
    and the raw distribution is still returned in the response's `mlRisk`
    field for backend logging.
    """
    # `base_verdict` / `ml_results` are accepted for API parity with callers
    # but no longer affect the user-visible string.
    del base_verdict, ml_results
    overall_risk = risk_from_score(final_score)
    high_checks = [item["check"] for item in signals if item["severity"] == "high"]
    medium_checks = [item["check"] for item in signals if item["severity"] == "medium"]

    if overall_risk == "high":
        if high_checks:
            return f"This QR code shows high-risk indicators in {', '.join(high_checks[:3])}. Do not continue unless you can independently verify the destination and sender."
        return "This QR code lands in SafeScan's high-risk range. Do not continue unless you can independently verify the destination and sender."
    if overall_risk == "suspicious":
        checks = medium_checks or high_checks
        if checks:
            return f"This QR code looks suspicious because {', '.join(checks[:3])} need review. Continue only after confirming the domain, redirect path, and wallet action."
        return "This QR code lands in SafeScan's review range. Confirm the destination before taking action."
    return "SafeScan did not find strong phishing or wallet-drain indicators in this QR payload. Still verify the destination before connecting a wallet or sending funds."

