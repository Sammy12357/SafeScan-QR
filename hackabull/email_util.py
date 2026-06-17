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
# OUTBOUND EMAIL (SMTP)
# Optional: configure SMTP_HOST / SMTP_USERNAME / SMTP_PASSWORD (and EMAIL_FROM)
# to enable transactional email such as the newsletter welcome message. When
# the variables are absent every send is a silent no-op, so the app runs fine
# without any email provider. Uses the standard library only — works with any
# SMTP service (Resend, SendGrid, Mailgun, Brevo, Gmail app password, ...).
# =============================================================================
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USERNAME).strip()
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "SafeScan QR").strip()


def email_sending_configured():
    """True when enough SMTP settings are present to attempt a send."""
    return bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and EMAIL_FROM)


def send_email(to_address, subject, html_body, text_body=None):
    """Send one email over SMTP (STARTTLS). Returns True on success.

    Blocking — call via ``asyncio.to_thread`` from async routes. Failures are
    logged and swallowed so an email outage can never break a user flow.
    """
    if not email_sending_configured() or not (to_address or "").strip():
        return False
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = f"{EMAIL_FROM_NAME} <{EMAIL_FROM}>" if EMAIL_FROM_NAME else EMAIL_FROM
    message["To"] = to_address.strip()
    message.attach(MIMEText(text_body or re.sub(r"<[^>]+>", " ", html_body), "plain"))
    message.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [to_address.strip()], message.as_string())
        return True
    except Exception as exc:
        print({"warning": "email send failed", "to": to_address, "error": f"{type(exc).__name__}: {exc}"})
        return False


