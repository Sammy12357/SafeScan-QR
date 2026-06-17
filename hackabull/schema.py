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
from .config import ADMIN_ACCESS_DENYLIST
from .config import ADMIN_EMAILS
from .config import OWNER_EMAILS

# =============================================================================
# DATABASE SCHEMA & INITIALIZATION
# Creates every SQLite table the app relies on. Idempotent: safe to call on
# each boot; existing tables/columns are left untouched.
# =============================================================================
def init_db():
    """Create all SQLite tables/indexes if they don't already exist.

    Called once at startup. Uses ``CREATE TABLE IF NOT EXISTS`` throughout, so
    it's safe to run on every boot and acts as the schema's single source of
    truth (users, sessions, scans, scan_history, wallets, fraud tables,
    subscriptions, audit logs, etc.).
    """
    conn = sqlite3.connect(database_path())
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_results (url TEXT PRIMARY KEY, status TEXT, timestamp TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS domain_age_cache (
                        domain TEXT PRIMARY KEY,
                        creation_date TEXT,
                        age_days INTEGER,
                        source TEXT,
                        fetched_at TEXT NOT NULL,
                        expires_on TEXT,
                        registrar TEXT,
                        error TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        google_id TEXT PRIMARY KEY,
                        email TEXT,
                        last_login TEXT,
                        role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin', 'owner')),
                        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted')),
                        last_login_at TEXT,
                        login_ip TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        deleted_at TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (email TEXT PRIMARY KEY, url_found TEXT, scan_count INTEGER DEFAULT 0, wallet_address TEXT, tokens_sent INTEGER DEFAULT 0)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_events
                        (email TEXT NOT NULL, payload_hash TEXT NOT NULL, url_found TEXT NOT NULL,
                         first_scanned_at TEXT NOT NULL, user_id TEXT,
                         PRIMARY KEY (email, payload_hash))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS consent_logs
                        (id TEXT PRIMARY KEY, user_id TEXT, ip_hash TEXT NOT NULL,
                         consent_given INTEGER NOT NULL, consent_type TEXT NOT NULL,
                         banner_version TEXT NOT NULL, timestamp TEXT NOT NULL,
                         user_agent TEXT, locale TEXT, expiry_date TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS data_requests
                        (id TEXT PRIMARY KEY, email TEXT NOT NULL, region TEXT,
                         request_type TEXT NOT NULL, details TEXT, status TEXT NOT NULL,
                         submitted_at TEXT NOT NULL, completed_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS breach_reports
                        (id TEXT PRIMARY KEY, discovery_date TEXT NOT NULL,
                         data_categories TEXT NOT NULL, users_affected TEXT NOT NULL,
                         likely_consequences TEXT NOT NULL, measures_taken TEXT NOT NULL,
                         created_at TEXT NOT NULL, template TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS age_confirmations
                        (email TEXT PRIMARY KEY, threshold INTEGER NOT NULL,
                         locale TEXT, confirmed_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS privacy_opt_outs
                        (id TEXT PRIMARY KEY, email TEXT NOT NULL, region TEXT,
                         opt_out_type TEXT NOT NULL, timestamp TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS waitlist_signups
                        (email TEXT PRIMARY KEY, source TEXT, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions
                        (id TEXT PRIMARY KEY, google_id TEXT NOT NULL,
                         created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         last_active TEXT NOT NULL, revoked_at TEXT,
                         ip_hash TEXT, user_agent TEXT,
                         FOREIGN KEY(google_id) REFERENCES users(google_id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS persistent_sessions
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                         token_hash TEXT NOT NULL UNIQUE,
                         created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         last_used TEXT, revoked_at TEXT,
                         ip_hash TEXT, user_agent TEXT,
                         FOREIGN KEY(user_id) REFERENCES users(google_id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                        (id TEXT PRIMARY KEY, actor_user_id TEXT, action TEXT NOT NULL,
                         target_type TEXT, target_id TEXT, metadata TEXT,
                         ip_address TEXT, user_agent TEXT, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS abuse_flags
                        (id TEXT PRIMARY KEY, email TEXT, flag_type TEXT NOT NULL,
                         detail TEXT NOT NULL, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_history
                        (id TEXT PRIMARY KEY, email TEXT NOT NULL, url TEXT NOT NULL,
                         risk_score INTEGER, verdict TEXT, signals TEXT,
                         reported INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                         classification TEXT NOT NULL DEFAULT 'UNKNOWN')''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS upload_artifacts
                        (id TEXT PRIMARY KEY, user_id TEXT, email TEXT,
                         object_key TEXT NOT NULL, backend TEXT NOT NULL,
                         content_type TEXT, byte_size INTEGER NOT NULL,
                         sha256 TEXT NOT NULL, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS url_reports
                        (id TEXT PRIMARY KEY, url TEXT NOT NULL, reporter_email TEXT,
                         reason TEXT NOT NULL, risk_score INTEGER, status TEXT NOT NULL DEFAULT 'pending',
                         created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS url_blocklist
                        (id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, reason TEXT,
                         added_by TEXT, created_at TEXT NOT NULL, removed_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS ip_registry
                        (id TEXT PRIMARY KEY, ip_address TEXT NOT NULL, user_id TEXT NOT NULL,
                         event_type TEXT NOT NULL, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_velocity
                        (user_id TEXT PRIMARY KEY, scans_last_hour INTEGER DEFAULT 0,
                         scans_last_day INTEGER DEFAULT 0, last_scan_at TEXT,
                         last_scan_url TEXT, duplicate_count INTEGER DEFAULT 0,
                         fast_scan_count INTEGER DEFAULT 0, updated_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS fraud_flags
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, check_name TEXT NOT NULL,
                         severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
                         reason TEXT NOT NULL, metadata TEXT, auto_disqualify INTEGER DEFAULT 0,
                         reviewed INTEGER DEFAULT 0, reviewed_by TEXT, reviewed_at TEXT,
                         review_outcome TEXT CHECK(review_outcome IN ('cleared','disqualified','escalated') OR review_outcome IS NULL),
                         created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_fingerprints
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                         first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                         UNIQUE(user_id, fingerprint))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS api_keys
                        (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hint TEXT NOT NULL,
                         key_hash TEXT NOT NULL, scopes TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                         created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
                         last_used_at TEXT, revoked_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS referrals
                        (id TEXT PRIMARY KEY, referrer_email TEXT NOT NULL, referred_email TEXT NOT NULL,
                         counted INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                         UNIQUE(referred_email))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallets
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE,
                         address TEXT NOT NULL UNIQUE, verified INTEGER NOT NULL DEFAULT 1,
                         connected_at TEXT NOT NULL, sol_balance REAL, tx_count INTEGER,
                         wallet_age_days INTEGER, onchain_verified_at TEXT,
                         disconnected_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallet_nonces
                        (user_id TEXT PRIMARY KEY, wallet_address TEXT NOT NULL,
                         nonce TEXT NOT NULL, message TEXT NOT NULL,
                         issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS alpha_subscriptions
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                         email TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'alpha_premium',
                         provider TEXT NOT NULL DEFAULT 'stripe',
                         status TEXT NOT NULL DEFAULT 'active',
                         purchased_at TEXT NOT NULL,
                         checkout_session_id TEXT, stripe_payment_link TEXT,
                         client_reference_id TEXT, metadata TEXT,
                         created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                         UNIQUE(user_id, tier, provider))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS alpha_solana_payment_references
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                         email TEXT NOT NULL, reference TEXT NOT NULL UNIQUE,
                         recipient TEXT NOT NULL, amount_sol TEXT NOT NULL,
                         amount_usd TEXT, sol_usd_price TEXT,
                         amount_lamports INTEGER, quote_expires_at TEXT,
                         status TEXT NOT NULL DEFAULT 'pending',
                         signature TEXT, created_at TEXT NOT NULL,
                         updated_at TEXT NOT NULL, expires_at TEXT,
                         UNIQUE(user_id, recipient, amount_sol, status))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS go_ghost_removal_jobs
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
                         broker TEXT NOT NULL, status TEXT NOT NULL, detail TEXT,
                         target_url TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_google_id ON sessions(google_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_age_cache_domain ON domain_age_cache(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_age_cache_fetched ON domain_age_cache(fetched_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_persistent_sessions_token_hash ON persistent_sessions(token_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_persistent_sessions_user_id ON persistent_sessions(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_abuse_email ON abuse_flags(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_email ON scan_history(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_upload_artifacts_user_id ON upload_artifacts(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON url_reports(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_url ON url_blocklist(url)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_registry_ip ON ip_registry(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_registry_user ON ip_registry(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_user ON fraud_flags(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_reviewed ON fraud_flags(reviewed)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_fingerprint ON device_fingerprints(fingerprint)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets(address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallet_nonces_wallet ON wallet_nonces(wallet_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_subscriptions_email ON alpha_subscriptions(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_subscriptions_purchased ON alpha_subscriptions(purchased_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_solana_reference ON alpha_solana_payment_references(reference)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_solana_user ON alpha_solana_payment_references(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_jobs_user ON go_ghost_removal_jobs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_jobs_broker ON go_ghost_removal_jobs(broker)")
    cursor.execute("PRAGMA table_info(users)")
    user_columns = {row[1] for row in cursor.fetchall()}
    user_migrations = {
        "role": "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin', 'owner'))",
        "status": "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted'))",
        "last_login_at": "ALTER TABLE users ADD COLUMN last_login_at TEXT",
        "login_ip": "ALTER TABLE users ADD COLUMN login_ip TEXT",
        "created_at": "ALTER TABLE users ADD COLUMN created_at TEXT",
        "deleted_at": "ALTER TABLE users ADD COLUMN deleted_at TEXT",
        "airdrop_status": "ALTER TABLE users ADD COLUMN airdrop_status TEXT NOT NULL DEFAULT 'eligible' CHECK(airdrop_status IN ('eligible','flagged','disqualified','cleared'))",
        "fraud_score": "ALTER TABLE users ADD COLUMN fraud_score INTEGER DEFAULT 0",
        "display_name": "ALTER TABLE users ADD COLUMN display_name TEXT",
        "picture": "ALTER TABLE users ADD COLUMN picture TEXT",
        "referral_code": "ALTER TABLE users ADD COLUMN referral_code TEXT",
    }
    for column, ddl in user_migrations.items():
        if column not in user_columns:
            cursor.execute(ddl)
    cursor.execute("PRAGMA table_info(alpha_subscriptions)")
    alpha_subscription_columns = {row[1] for row in cursor.fetchall()}
    alpha_subscription_migrations = {
        "stripe_customer_id": "ALTER TABLE alpha_subscriptions ADD COLUMN stripe_customer_id TEXT",
        "stripe_subscription_id": "ALTER TABLE alpha_subscriptions ADD COLUMN stripe_subscription_id TEXT",
        "current_period_start": "ALTER TABLE alpha_subscriptions ADD COLUMN current_period_start TEXT",
        "current_period_end": "ALTER TABLE alpha_subscriptions ADD COLUMN current_period_end TEXT",
        "cancel_at_period_end": "ALTER TABLE alpha_subscriptions ADD COLUMN cancel_at_period_end INTEGER NOT NULL DEFAULT 0",
        "canceled_at": "ALTER TABLE alpha_subscriptions ADD COLUMN canceled_at TEXT",
        "expires_at": "ALTER TABLE alpha_subscriptions ADD COLUMN expires_at TEXT",
    }
    for column, ddl in alpha_subscription_migrations.items():
        if column not in alpha_subscription_columns:
            cursor.execute(ddl)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_subscriptions_stripe_subscription ON alpha_subscriptions(stripe_subscription_id)")
    cursor.execute("PRAGMA table_info(alpha_solana_payment_references)")
    alpha_solana_columns = {row[1] for row in cursor.fetchall()}
    alpha_solana_migrations = {
        "amount_usd": "ALTER TABLE alpha_solana_payment_references ADD COLUMN amount_usd TEXT",
        "sol_usd_price": "ALTER TABLE alpha_solana_payment_references ADD COLUMN sol_usd_price TEXT",
        "amount_lamports": "ALTER TABLE alpha_solana_payment_references ADD COLUMN amount_lamports INTEGER",
        "quote_expires_at": "ALTER TABLE alpha_solana_payment_references ADD COLUMN quote_expires_at TEXT",
    }
    for column, ddl in alpha_solana_migrations.items():
        if column not in alpha_solana_columns:
            cursor.execute(ddl)
    cursor.execute("PRAGMA table_info(domain_age_cache)")
    domain_age_columns = {row[1] for row in cursor.fetchall()}
    domain_age_migrations = {
        "expires_on": "ALTER TABLE domain_age_cache ADD COLUMN expires_on TEXT",
        "registrar": "ALTER TABLE domain_age_cache ADD COLUMN registrar TEXT",
        "error": "ALTER TABLE domain_age_cache ADD COLUMN error TEXT",
    }
    for column, ddl in domain_age_migrations.items():
        if column not in domain_age_columns:
            cursor.execute(ddl)
    if "google_sub" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
    if "username" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN username TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username)) WHERE username IS NOT NULL AND username != ''")
    if ADMIN_ACCESS_DENYLIST:
        placeholders = ",".join("?" for _ in ADMIN_ACCESS_DENYLIST)
        cursor.execute(
            f"UPDATE users SET role = 'user' WHERE lower(email) IN ({placeholders}) AND role IN ('admin', 'owner')",
            tuple(sorted(ADMIN_ACCESS_DENYLIST))
        )
    if ADMIN_EMAILS:
        placeholders = ",".join("?" for _ in ADMIN_EMAILS)
        cursor.execute(
            f"UPDATE users SET role = 'admin' WHERE lower(email) IN ({placeholders}) AND role != 'owner'",
            tuple(sorted(ADMIN_EMAILS))
        )
    if OWNER_EMAILS:
        placeholders = ",".join("?" for _ in OWNER_EMAILS)
        cursor.execute(
            f"UPDATE users SET role = 'owner' WHERE lower(email) IN ({placeholders})",
            tuple(sorted(OWNER_EMAILS))
        )
    cursor.execute("UPDATE users SET created_at = COALESCE(created_at, last_login, ?)", (datetime.utcnow().isoformat() + "Z",))
    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = {row[1] for row in cursor.fetchall()}
    if "airdrop_eligible" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_eligible INTEGER DEFAULT 0")
    if "airdrop_tokens_sent" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_tokens_sent INTEGER DEFAULT 0")
    if "airdrop_sent_at" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_sent_at TEXT")
    if "user_id" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
    cursor.execute("UPDATE scans SET airdrop_eligible = 1 WHERE scan_count >= 5")
    cursor.execute("PRAGMA table_info(scan_history)")
    scan_history_columns = {row[1] for row in cursor.fetchall()}
    if "user_id" not in scan_history_columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id TEXT")
    if "classification" not in scan_history_columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN classification TEXT NOT NULL DEFAULT 'UNKNOWN'")
    cursor.execute("""
        UPDATE scan_history
        SET classification = CASE
            WHEN upper(COALESCE(verdict, '')) IN ('MALICIOUS', 'HIGH', 'DANGER') OR COALESCE(risk_score, 0) >= 80 THEN 'MALICIOUS'
            WHEN upper(COALESCE(verdict, '')) IN ('CAUTION', 'SUSPICIOUS', 'MEDIUM') OR COALESCE(risk_score, 0) >= 40 THEN 'CAUTION'
            WHEN upper(COALESCE(verdict, '')) = 'SAFE' OR COALESCE(risk_score, 0) < 40 THEN 'SAFE'
            ELSE 'UNKNOWN'
        END
        WHERE classification IS NULL OR classification = '' OR classification = 'UNKNOWN'
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_classification ON scan_history(classification)")
    cursor.execute("PRAGMA table_info(scan_events)")
    scan_event_columns = {row[1] for row in cursor.fetchall()}
    if "user_id" not in scan_event_columns:
        cursor.execute("ALTER TABLE scan_events ADD COLUMN user_id TEXT")
    cursor.execute("""
        UPDATE scan_history
        SET user_id = (
            SELECT users.google_id
            FROM users
            WHERE lower(users.email) = lower(scan_history.email)
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)
    cursor.execute("""
        UPDATE scans
        SET user_id = (
            SELECT users.google_id
            FROM users
            WHERE lower(users.email) = lower(scans.email)
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)
    cursor.execute("""
        UPDATE scan_events
        SET user_id = (
            SELECT users.google_id
            FROM users
            WHERE lower(users.email) = lower(scan_events.email)
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_user_id ON scan_events(user_id)")
    cursor.execute('''CREATE TABLE IF NOT EXISTS local_credentials
                        (email TEXT PRIMARY KEY,
                         password_hash TEXT NOT NULL,
                         created_at TEXT NOT NULL,
                         user_id TEXT)''')
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_local_credentials_email_lower ON local_credentials(lower(email))")
    # Discord account links. Both columns are unique on purpose: one SafeScan
    # account links to one Discord account and vice versa, so a single Discord
    # user can't "verify" many SafeScan accounts to farm airdrop perks.
    cursor.execute('''CREATE TABLE IF NOT EXISTS discord_links
                        (id TEXT PRIMARY KEY,
                         user_id TEXT NOT NULL UNIQUE,
                         discord_id TEXT NOT NULL UNIQUE,
                         discord_username TEXT,
                         guild_member INTEGER DEFAULT 0,
                         role_granted INTEGER DEFAULT 0,
                         linked_at TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

def db_connect():
    return get_conn()

