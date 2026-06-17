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
from .leaderboard import MALICIOUS_RISK_THRESHOLD
from .leaderboard import _like_escape

# =============================================================================
# MALICIOUS QR DATABASE (public catalogue of known-bad codes)
# =============================================================================
def _threat_category(score):
    if score >= 90:
        return "Critical"
    if score >= MALICIOUS_RISK_THRESHOLD:
        return "Malicious"
    return "Suspicious"

def get_malicious_qr_codes(page=1, limit=20, query=""):
    """Public, global list of scanned QR payloads flagged malicious.

    Aggregates scan_history by URL so each dangerous code appears once, with
    its highest risk score, most recent sighting, and how many times it has
    been seen. Deliberately exposes no scanner identity (no email / user id) —
    this is a public "codes to avoid" board, not user history.
    """
    page = max(1, int(page or 1))
    limit = max(1, min(int(limit or 20), 100))
    offset = (page - 1) * limit
    search = (query or "").strip()[:200]

    where_base = (
        "WHERE (COALESCE(risk_score, 0) >= ? OR upper(COALESCE(verdict, '')) = 'MALICIOUS') "
        "AND url IS NOT NULL AND url != ''"
    )
    base_params = [MALICIOUS_RISK_THRESHOLD]

    where = where_base
    params = list(base_params)
    if search:
        where += " AND lower(url) LIKE ? ESCAPE '\\'"
        params.append("%" + _like_escape(search.lower()) + "%")

    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(
            f"SELECT COUNT(*) FROM (SELECT url FROM scan_history {where} GROUP BY url)",
            params,
        ).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT url,
                   MAX(COALESCE(risk_score, 0)) AS risk_score,
                   MAX(created_at) AS last_seen,
                   COUNT(*) AS times_seen
            FROM scan_history
            {where}
            GROUP BY url
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()

        # Global stats are independent of the current search filter so the
        # summary always reflects the full threat database.
        stats_row = conn.execute(
            f"""
            SELECT COUNT(*) AS total_urls,
                   COALESCE(SUM(times_seen), 0) AS total_sightings,
                   COALESCE(SUM(CASE WHEN risk_score >= 90 THEN 1 ELSE 0 END), 0) AS critical_count,
                   COALESCE(SUM(CASE WHEN risk_score >= ? AND risk_score < 90 THEN 1 ELSE 0 END), 0) AS malicious_count,
                   COALESCE(SUM(CASE WHEN risk_score < ? THEN 1 ELSE 0 END), 0) AS suspicious_count,
                   MAX(last_seen) AS last_updated
            FROM (
                SELECT url,
                       MAX(COALESCE(risk_score, 0)) AS risk_score,
                       MAX(created_at) AS last_seen,
                       COUNT(*) AS times_seen
                FROM scan_history
                {where_base}
                GROUP BY url
            )
            """,
            base_params + base_params,
        ).fetchone()

    entries = []
    for row in rows:
        score = int(row["risk_score"] or 0)
        url = row["url"] or ""
        entries.append({
            "id": hashlib.sha256(url.encode("utf-8")).hexdigest()[:16],
            "url": url,
            "riskScore": score,
            "category": _threat_category(score),
            "lastScannedAt": row["last_seen"],
            "timesSeen": int(row["times_seen"] or 0),
        })
    total = int(total or 0)
    return {
        "entries": entries,
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": max(1, (total + limit - 1) // limit),
        "stats": {
            "totalUrls": int(stats_row["total_urls"] or 0),
            "totalSightings": int(stats_row["total_sightings"] or 0),
            "criticalCount": int(stats_row["critical_count"] or 0),
            "maliciousCount": int(stats_row["malicious_count"] or 0),
            "suspiciousCount": int(stats_row["suspicious_count"] or 0),
            "lastUpdated": stats_row["last_updated"],
        },
    }

def render_threat_qr_png(url):
    """Regenerate the QR graphic for a known-malicious URL, stamped with a red
    warning badge so it reads as dangerous and is shown for awareness only."""
    import qrcode
    from qrcode.constants import ERROR_CORRECT_H
    from PIL import Image, ImageDraw

    qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_H, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    # Dark-red modules signal "danger" at a glance versus the safe black codes.
    img = qr.make_image(fill_color="#7f1d1d", back_color="white").convert("RGB")
    img_w, img_h = img.size
    cx, cy = img_w // 2, img_h // 2
    draw = ImageDraw.Draw(img)

    badge = max(48, img_w // 4)
    half = badge // 2
    pad = max(6, badge // 12)
    corner = max(6, badge // 6)
    draw.rounded_rectangle(
        [cx - half - pad, cy - half - pad, cx + half + pad, cy + half + pad],
        radius=corner + pad, fill="white")
    draw.rounded_rectangle(
        [cx - half, cy - half, cx + half, cy + half],
        radius=corner, outline="#dc2626", width=max(3, badge // 16))
    # Exclamation mark: a tapered bar plus a dot.
    bar_w = max(4, badge // 9)
    draw.rounded_rectangle(
        [cx - bar_w // 2, cy - half + badge // 5, cx + bar_w // 2, cy + half // 4],
        radius=bar_w // 2, fill="#dc2626")
    dot_r = max(3, bar_w // 2)
    dot_cy = cy + half - badge // 5
    draw.ellipse([cx - dot_r, dot_cy - dot_r, cx + dot_r, dot_cy + dot_r], fill="#dc2626")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()

