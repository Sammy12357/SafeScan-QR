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
from .config import DOMAIN_AGE_CACHE_TTL_DAYS
from .config import SECURITYTRAILS_API_KEY
from .config import WHOISXML_API_KEY
from .lowlevel import normalize_url

# =============================================================================
# DOMAIN AGE (WHOIS / RDAP / WHOISXML / SecurityTrails / Wayback)
# Newly registered domains are a strong phishing signal; this looks up a
# domain's creation date across several providers and caches the result.
# =============================================================================
def parse_rdap_event_date(events, actions):
    actions = set(actions)
    for event in events or []:
        if event.get("eventAction") in actions:
            return event.get("eventDate")
    return None

def extract_domain_for_age(target_url):
    parsed = urlparse(normalize_url(target_url))
    hostname = (parsed.hostname or "").strip(".").lower()
    if not hostname:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        pass
    try:
        import tldextract
        extracted = tldextract.extract(hostname)
        registrable = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
        return registrable or hostname.removeprefix("www.")
    except Exception:
        parts = hostname.removeprefix("www.").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def domain_age_days(created_date):
    created = parse_domain_datetime(created_date)
    if not created:
        raise ValueError("Invalid creation date")
    return max(0, (datetime.utcnow() - created).days)

def domain_age_risk_level(age_days):
    if age_days is None:
        return "unknown"
    if age_days >= 365:
        return "established"
    if age_days >= 90:
        return "recent"
    return "new"

def domain_age_signal_tier(age_days):
    if age_days is None:
        return "unknown", "low", "Age unknown", "Could not verify domain registration age."
    if age_days < 7:
        return "very_new", "high", "Very new domain", "Domain was registered less than 7 days ago, a critical phishing indicator."
    if age_days < 30:
        return "new", "high", "New domain", "Domain was registered less than 30 days ago, a strong phishing indicator."
    if age_days < 90:
        return "young", "medium", "Young domain", "Domain was registered less than 90 days ago and warrants extra caution."
    if age_days < 365:
        return "recent", "low", "Recent domain", "Domain was registered less than one year ago."
    return "established", "low", "Established domain", "Domain has been registered for over one year."

def format_domain_age(age_days):
    if age_days is None:
        return "Age unknown"
    years = age_days // 365
    months = (age_days % 365) // 30
    days = age_days % 30
    if years:
        return f"{years} year{'s' if years != 1 else ''}, {months} month{'s' if months != 1 else ''}"
    if months:
        return f"{months} month{'s' if months != 1 else ''}, {days} day{'s' if days != 1 else ''}"
    return f"{age_days} day{'s' if age_days != 1 else ''}"

def parse_domain_datetime(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        for candidate in (
            raw,
            raw.replace("Z", "+00:00"),
            raw.split(".", 1)[0],
            raw[:19],
        ):
            try:
                parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                break
            except ValueError:
                parsed = None
        if parsed is None:
            for fmt in ("%Y-%m-%d", "%Y%m%d%H%M%S", "%Y.%m.%d %H:%M:%S", "%d-%b-%Y"):
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    parsed = None
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed

def first_domain_datetime(value):
    if isinstance(value, (list, tuple)):
        values = value
    else:
        values = [value]
    parsed_values = [parse_domain_datetime(item) for item in values]
    parsed_values = [item for item in parsed_values if item is not None]
    return min(parsed_values) if parsed_values else None

def extract_rdap_registrar(rdap):
    registrar = rdap.get("registrar")
    if registrar:
        return registrar if isinstance(registrar, str) else registrar.get("name") or registrar.get("handle")
    for entity in rdap.get("entities", []) or []:
        vcard = entity.get("vcardArray", [])
        rows = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        for row in rows:
            if isinstance(row, list) and len(row) > 3 and row[0] == "fn":
                return row[3]
        if entity.get("handle"):
            return entity.get("handle")
    return None

def unknown_domain_age_result(domain):
    return {
        "domain": domain,
        "registeredOn": None,
        "creationDate": None,
        "expiresOn": None,
        "registrar": None,
        "ageInDays": None,
        "ageDays": None,
        "ageLabel": "Age unknown",
        "riskLevel": "unknown",
        "riskLabel": "Age unknown",
        "riskDetail": "WHOIS/RDAP data unavailable.",
        "source": "unavailable",
        "error": "Domain age lookup unavailable.",
    }

def lookup_domain_age_result(target_url):
    domain = extract_domain_for_age(target_url)
    if not domain:
        return unknown_domain_age_result("")
    return get_domain_age_days(domain)

def domain_age_cache_get(domain):
    cutoff = (datetime.utcnow() - timedelta(days=DOMAIN_AGE_CACHE_TTL_DAYS)).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            """SELECT domain, creation_date, age_days, source, fetched_at, expires_on, registrar, error
               FROM domain_age_cache
               WHERE domain = ? AND fetched_at > ?""",
            (domain, cutoff),
        ).fetchone()
    if not row:
        return None
    return {
        "domain": row["domain"],
        "creation_date": row["creation_date"],
        "age_days": row["age_days"],
        "source": row["source"] or "cache",
        "expires_on": row["expires_on"],
        "registrar": row["registrar"],
        "error": row["error"],
    }

def domain_age_cache_save(domain, result):
    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO domain_age_cache
               (domain, creation_date, age_days, source, fetched_at, expires_on, registrar, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                domain,
                result.get("creation_date"),
                result.get("age_days"),
                result.get("source"),
                datetime.utcnow().isoformat() + "Z",
                result.get("expires_on"),
                result.get("registrar"),
                result.get("error"),
            ),
        )

def fetch_domain_age_whois(domain):
    import whois as pywhois
    record = pywhois.whois(domain)
    def record_value(key):
        value = getattr(record, key, None)
        if value is not None:
            return value
        return record.get(key) if hasattr(record, "get") else None
    created = first_domain_datetime(record_value("creation_date"))
    if not created:
        return None
    expires = first_domain_datetime(record_value("expiration_date"))
    registrar = record_value("registrar")
    return {
        "creation_date": created.isoformat() + "Z",
        "age_days": max(0, (datetime.utcnow() - created).days),
        "source": "whois",
        "expires_on": expires.isoformat() + "Z" if expires else None,
        "registrar": registrar[0] if isinstance(registrar, list) and registrar else registrar,
        "error": None,
    }

def fetch_domain_age_rdap(domain):
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        response.raise_for_status()
        rdap = response.json()
    except (requests.RequestException, ValueError):
        return None

    events = rdap.get("events", [])
    registered_on = parse_rdap_event_date(events, ("registration", "domain registration", "creation"))
    expires_on = parse_rdap_event_date(events, ("expiration", "expiry"))
    registrar = extract_rdap_registrar(rdap)
    created = parse_domain_datetime(registered_on)
    if not created:
        return None
    return {
        "creation_date": created.isoformat() + "Z",
        "age_days": max(0, (datetime.utcnow() - created).days),
        "source": "rdap",
        "expires_on": expires_on,
        "registrar": registrar,
        "error": None,
    }

def fetch_domain_age_whoisxml(domain):
    if not WHOISXML_API_KEY:
        return None
    response = requests.get(
        "https://www.whoisxmlapi.com/whoisserver/WhoisService",
        params={"apiKey": WHOISXML_API_KEY, "domainName": domain, "outputFormat": "JSON"},
        timeout=6,
    )
    response.raise_for_status()
    data = response.json()
    record = data.get("WhoisRecord", {}) if isinstance(data, dict) else {}
    registry = record.get("registryData") or {}
    created = parse_domain_datetime(registry.get("createdDate") or record.get("createdDate"))
    if not created:
        return None
    expires = parse_domain_datetime(registry.get("expiresDate") or record.get("expiresDate"))
    return {
        "creation_date": created.isoformat() + "Z",
        "age_days": max(0, (datetime.utcnow() - created).days),
        "source": "whoisxml",
        "expires_on": expires.isoformat() + "Z" if expires else None,
        "registrar": (registry.get("registrarName") or record.get("registrarName")),
        "error": None,
    }

def fetch_domain_age_securitytrails(domain):
    if not SECURITYTRAILS_API_KEY:
        return None
    response = requests.get(
        f"https://api.securitytrails.com/v1/domain/{domain}",
        headers={"APIKEY": SECURITYTRAILS_API_KEY},
        timeout=6,
    )
    response.raise_for_status()
    data = response.json()
    created = parse_domain_datetime(data.get("created_date") or data.get("createdDate"))
    if not created:
        return None
    expires = parse_domain_datetime(data.get("expires_date") or data.get("expiresDate"))
    return {
        "creation_date": created.isoformat() + "Z",
        "age_days": max(0, (datetime.utcnow() - created).days),
        "source": "securitytrails",
        "expires_on": expires.isoformat() + "Z" if expires else None,
        "registrar": data.get("registrar"),
        "error": None,
    }

def fetch_domain_age_wayback(domain):
    response = requests.get(
        "https://archive.org/wayback/available",
        params={"url": domain},
        timeout=6,
    )
    response.raise_for_status()
    data = response.json()
    timestamp = ((data.get("archived_snapshots", {}) or {}).get("closest") or {}).get("timestamp")
    created = parse_domain_datetime(timestamp)
    if not created:
        return None
    return {
        "creation_date": created.isoformat() + "Z",
        "age_days": max(0, (datetime.utcnow() - created).days),
        "source": "wayback_lower_bound",
        "expires_on": None,
        "registrar": None,
        "error": None,
    }

def fetch_domain_age(domain):
    errors = []
    strategies = (
        ("whois", fetch_domain_age_whois),
        ("rdap", fetch_domain_age_rdap),
        ("whoisxml", fetch_domain_age_whoisxml),
        ("securitytrails", fetch_domain_age_securitytrails),
        ("wayback", fetch_domain_age_wayback),
    )
    for source, strategy in strategies:
        try:
            result = strategy(domain)
            if result and result.get("age_days") is not None:
                return result
        except Exception as exc:
            errors.append(f"{source}: {type(exc).__name__}")
    return {
        "creation_date": None,
        "age_days": None,
        "source": "unavailable",
        "expires_on": None,
        "registrar": None,
        "error": "; ".join(errors) or "All domain age sources failed or timed out",
    }

def domain_age_lookup_to_ui(domain, result):
    age_days = result.get("age_days")
    risk_level, severity, risk_label, risk_detail = domain_age_signal_tier(age_days)
    ui_risk_level = "new" if risk_level in ("very_new", "new", "young") else risk_level
    if result.get("source") == "wayback_lower_bound" and age_days is not None:
        risk_detail = f"Earliest archived snapshot is {format_domain_age(age_days)} old; true registration may be older."
    elif result.get("error"):
        risk_detail = f"Could not verify domain registration age ({result.get('error')})."
    return {
        "domain": domain,
        "registeredOn": result.get("creation_date"),
        "creationDate": result.get("creation_date"),
        "expiresOn": result.get("expires_on"),
        "registrar": result.get("registrar"),
        "ageInDays": age_days,
        "ageDays": age_days,
        "ageLabel": format_domain_age(age_days),
        "riskLevel": ui_risk_level,
        "signalLevel": risk_level,
        "riskLabel": risk_label,
        "riskDetail": risk_detail,
        "severity": severity,
        "source": result.get("source") or "unavailable",
        "error": result.get("error"),
    }

def get_domain_age_days(domain):
    cached = domain_age_cache_get(domain)
    if cached:
        return domain_age_lookup_to_ui(domain, cached)
    result = fetch_domain_age(domain)
    domain_age_cache_save(domain, result)
    return domain_age_lookup_to_ui(domain, result)

async def get_domain_age_days_async(domain):
    return await asyncio.to_thread(get_domain_age_days, domain)

