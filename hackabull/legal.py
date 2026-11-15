from __future__ import annotations
import requests
import json
import warnings
import io
import sqlite3
import logging
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
    unique_email_owner,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .config import ADMIN_EMAIL
from .config import CLIENT_ID
from .config import LEGAL_LAST_UPDATED
from .config import LEGAL_VERSION

# =============================================================================
# LEGAL PAGES, LOCALE & GDPR DATA EXPORT/DELETE
# =============================================================================
def legal_context(request: Request, title, body_html):
    return {
        "request": request,
        "title": title,
        "body_html": body_html,
        "last_updated": LEGAL_LAST_UPDATED,
        "version": LEGAL_VERSION,
        "admin_email": ADMIN_EMAIL,
        "google_client_id": CLIENT_ID
    }


_GO_GHOST_STATUS_TABLES = frozenset({
    "go_ghost_subjects", "go_ghost_consents", "go_ghost_requests",
})


def _go_ghost_status_table_exists(conn, table):
    if table not in _GO_GHOST_STATUS_TABLES:
        raise ValueError("Unknown Go Ghost status table")
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _go_ghost_status_export(conn, table, user_id):
    if not _go_ghost_status_table_exists(conn, table):
        return []
    return [dict(row) for row in conn.execute(
        f"SELECT * FROM {table} WHERE user_id = ?", (user_id,)
    )]

def get_user_export(email, user_id):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        if not unique_email_owner(conn, email, user_id):
            count_queries = (
                "SELECT COUNT(*) FROM scans WHERE user_id = ? OR lower(email) = lower(?)",
                "SELECT COUNT(*) FROM scan_events WHERE user_id = ? OR lower(email) = lower(?)",
                "SELECT COUNT(*) FROM scan_history WHERE user_id = ? OR lower(email) = lower(?)",
            )
            count = sum(conn.execute(query, (user_id, email)).fetchone()[0] for query in count_queries)
            if count:
                logging.getLogger(__name__).warning(
                    "Withheld %d scan rows from ambiguous privacy export pending ownership review", count
                )
            return None
        scans = [dict(row) for row in conn.execute(
            "SELECT * FROM scans WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )]
        events = [dict(row) for row in conn.execute(
            "SELECT * FROM scan_events WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )]
        requests_ = [dict(row) for row in conn.execute("SELECT * FROM data_requests WHERE email = ?", (email,))]
        age = [dict(row) for row in conn.execute("SELECT * FROM age_confirmations WHERE email = ?", (email,))]
        opt_outs = [dict(row) for row in conn.execute("SELECT * FROM privacy_opt_outs WHERE email = ?", (email,))]
        ghost_subjects = _go_ghost_status_export(conn, "go_ghost_subjects", user_id)
        ghost_consents = _go_ghost_status_export(conn, "go_ghost_consents", user_id)
        ghost_requests = _go_ghost_status_export(conn, "go_ghost_requests", user_id)
        ghost_legacy_jobs = [dict(row) for row in conn.execute(
            "SELECT * FROM go_ghost_removal_jobs WHERE user_id = ?", (user_id,)
        )]
    return {"email": email, "scans": scans, "scanEvents": events,
            "dataRequests": requests_, "ageConfirmations": age,
            "privacyOptOuts": opt_outs,
            "goGhostSubjects": ghost_subjects, "goGhostConsents": ghost_consents,
            "goGhostRequests": ghost_requests, "goGhostLegacyJobs": ghost_legacy_jobs}

def delete_user_data(email, user_id):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not unique_email_owner(conn, email, user_id):
            return False
        conn.execute(
            "DELETE FROM scans WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )
        conn.execute(
            "DELETE FROM scan_events WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )
        conn.execute(
            "DELETE FROM scan_history WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )
        # SQLite connections do not currently enforce foreign keys. Delete
        # each Go Ghost table explicitly, including the retired PII-bearing jobs.
        for table in ("go_ghost_requests", "go_ghost_consents", "go_ghost_subjects"):
            if _go_ghost_status_table_exists(conn, table):
                conn.execute(f"DELETE FROM {table} WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM go_ghost_removal_jobs WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE google_id = ?", (user_id,))
        conn.execute("DELETE FROM age_confirmations WHERE email = ?", (email,))
    return True

