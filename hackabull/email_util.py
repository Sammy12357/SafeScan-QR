"""Small, explicitly classified SMTP sender for SafeScan email.

The waitlist confirmation is a transactional proof-of-address message. Product
updates are marketing and fail closed until sender and postal details exist.
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
from email.message import EmailMessage
from email.utils import parseaddr
from html import escape
from urllib.parse import urlparse

from db import get_conn

from .config import APP_URL

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "SafeScan QR").strip()
COMPANY_LEGAL_NAME = os.getenv("COMPANY_LEGAL_NAME", "").strip()
COMPANY_POSTAL_ADDRESS = os.getenv("COMPANY_POSTAL_ADDRESS", "").strip()

EMAIL_TEMPLATES = {
    "waitlist_confirmation": "transactional",
    "waitlist_update": "marketing",
}


def _valid_email_address(value: str) -> bool:
    name, address = parseaddr(value or "")
    return bool(not name and address == value and re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", address))


def _real_setting(value: str) -> bool:
    stripped = (value or "").strip()
    if not stripped or "\r" in stripped or "\n" in stripped or len(stripped) > 500:
        return False
    return not any(marker in stripped.lower() for marker in ("your-", "your ", "replace", "placeholder", "example.com", "todo"))


def email_sending_configured() -> bool:
    """Whether the SMTP sender can attempt a transactional message."""
    return bool(
        SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD
        and _valid_email_address(EMAIL_FROM)
        and "\r" not in EMAIL_FROM_NAME and "\n" not in EMAIL_FROM_NAME
    )


def marketing_email_configured() -> bool:
    """A technical gate; the business owner must still verify the address."""
    return bool(
        email_sending_configured()
        and _real_setting(COMPANY_LEGAL_NAME)
        and _real_setting(COMPANY_POSTAL_ADDRESS)
    )


def _subscribed_and_unsuppressed(email: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            """SELECT 1 FROM waitlist_signups AS w
               WHERE w.email = ? AND w.confirmed_at IS NOT NULL
                 AND NOT EXISTS (
                    SELECT 1 FROM email_suppressions AS s WHERE s.email = w.email
                 )""",
            (email,),
        ).fetchone()
    return row is not None


def _unsubscribe_url_allowed(url: str) -> bool:
    target = urlparse(url or "")
    app = urlparse(APP_URL)
    return bool(
        target.scheme == app.scheme
        and target.netloc == app.netloc
        and target.path == "/waitlist/unsubscribe"
        and target.query.startswith("token=")
        and not target.fragment
        and (target.scheme == "https" or app.hostname in {"localhost", "127.0.0.1", "testserver"})
        and "\r" not in url and "\n" not in url
    )


def send_email(
    to_address: str,
    subject: str,
    html_body: str,
    text_body: str | None = None,
    *,
    template_id: str,
    unsubscribe_url: str | None = None,
) -> bool:
    """Send one classified message; no recipient or bearer URL is logged.

    This is blocking; async routes call it with ``asyncio.to_thread``. Every
    marketing send rechecks consent and suppression immediately before SMTP.
    """
    kind = EMAIL_TEMPLATES.get(template_id)
    if kind is None:
        raise ValueError("Unknown email template classification")
    recipient = (to_address or "").strip().lower()
    if not email_sending_configured() or not _valid_email_address(recipient):
        return False
    if not subject or "\r" in subject or "\n" in subject:
        return False

    if kind == "marketing":
        if not marketing_email_configured() or not unsubscribe_url or not _unsubscribe_url_allowed(unsubscribe_url):
            return False
        if not _subscribed_and_unsuppressed(recipient):
            return False
        legal_name = COMPANY_LEGAL_NAME
        postal_html = escape(COMPANY_POSTAL_ADDRESS).replace("\n", "<br>")
        plain_body = (text_body or re.sub(r"<[^>]+>", " ", html_body)).strip()
        html_body += (
            "<hr><p>Sent by " + escape(legal_name) + ".<br>" + postal_html
            + "<br><a href=\"" + escape(unsubscribe_url, quote=True) + "\">Unsubscribe</a></p>"
        )
        text_body = plain_body + f"\n\nSent by {legal_name}.\n{COMPANY_POSTAL_ADDRESS}\nUnsubscribe: {unsubscribe_url}"
    else:
        if unsubscribe_url:
            raise ValueError("Transactional template cannot carry a marketing unsubscribe header")
        text_body = text_body or re.sub(r"<[^>]+>", " ", html_body)

    message = EmailMessage()
    message["Subject"] = subject
    display_name = COMPANY_LEGAL_NAME if kind == "marketing" else EMAIL_FROM_NAME
    message["From"] = f"{display_name} <{EMAIL_FROM}>" if display_name else EMAIL_FROM
    message["To"] = recipient
    if kind == "marketing":
        message["List-Unsubscribe"] = f"<{unsubscribe_url}>"
        message["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            # Check again as close to delivery as possible. A concurrent
            # unsubscribe may still race the remote server's acceptance.
            if kind == "marketing" and not _subscribed_and_unsuppressed(recipient):
                return False
            server.send_message(message, from_addr=EMAIL_FROM, to_addrs=[recipient])
        return True
    except Exception as exc:
        logging.getLogger("safescan.email").warning("email_send_failed: %s", type(exc).__name__)
        return False
