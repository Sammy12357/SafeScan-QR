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

def get_user_export(email):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        scans = [dict(row) for row in conn.execute("SELECT * FROM scans WHERE email = ?", (email,))]
        events = [dict(row) for row in conn.execute("SELECT * FROM scan_events WHERE email = ?", (email,))]
        requests_ = [dict(row) for row in conn.execute("SELECT * FROM data_requests WHERE email = ?", (email,))]
        age = [dict(row) for row in conn.execute("SELECT * FROM age_confirmations WHERE email = ?", (email,))]
        opt_outs = [dict(row) for row in conn.execute("SELECT * FROM privacy_opt_outs WHERE email = ?", (email,))]
    return {"email": email, "scans": scans, "scanEvents": events, "dataRequests": requests_, "ageConfirmations": age, "privacyOptOuts": opt_outs}

def delete_user_data(email):
    with get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE email = ?", (email,))
        conn.execute("DELETE FROM scan_events WHERE email = ?", (email,))
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.execute("DELETE FROM age_confirmations WHERE email = ?", (email,))

