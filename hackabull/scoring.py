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

# =============================================================================
# RISK SIGNALS & SCORING
# A "signal" is one check's result; signals are aggregated into a 0-100 score
# which maps to an overall risk band and a safe/suspicious/malicious status.
# =============================================================================
def risk_reason(label, severity, detail):
    return {"label": label, "severity": severity, "detail": detail}

def signal(check, result, severity, description, passed=True):
    return {
        "check": check,
        "label": check,
        "result": result,
        "severity": severity,
        "description": description,
        "detail": description,
        "passed": passed
    }

def score_from_signals(signals):
    high_count = sum(1 for item in signals if item["severity"] == "high")
    medium_count = sum(1 for item in signals if item["severity"] == "medium")
    low_count = sum(1 for item in signals if item["severity"] == "low")
    score = min(80, high_count * 40) + medium_count * 15 + low_count * 5
    malicious_signal_checks = {
        "Brand Impersonation",
        "Google Safe Browsing",
        "Google Web Risk",
        "PhishTank",
        "Crypto Pattern",
        "Ethereum Approval Pattern",
        "Token Permit Pattern",
        "NFT Approval Pattern",
        "Known Malicious Contract",
        "Solana Address Placement",
    }
    has_malicious_signal = any(
        item.get("severity") == "high" and item.get("check") in malicious_signal_checks
        for item in signals
    )
    if has_malicious_signal:
        score = max(score, 85)
    if high_count >= 2 and medium_count >= 1:
        score = max(score, 90)
    elif high_count == 1 and medium_count >= 2:
        score = max(score, 75)
    return min(score, 100)

def risk_from_score(score):
    if score >= 80:
        return "high"
    if score >= 35:
        return "suspicious"
    return "safe"

def status_from_risk(overall_risk):
    return {"high": "MALICIOUS", "suspicious": "CAUTION", "safe": "SAFE"}.get(overall_risk, "CAUTION")

def severity_rank(item):
    return {"high": 0, "medium": 1, "low": 2}.get(item.get("severity"), 3)

def clamp_score(score):
    return max(0, min(100, int(round(float(score or 0)))))

