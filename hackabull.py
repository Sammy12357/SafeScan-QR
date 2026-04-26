import requests
import json
import warnings
import io
import sqlite3
import hashlib
import traceback
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
from pyzbar.pyzbar import decode

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os
from dotenv import load_dotenv
from distribute import airdrop_sweep

warnings.filterwarnings("ignore", category=ImportWarning)
load_dotenv()

CLIENT_ID = os.getenv("googe_client_id")
api_key = os.getenv("googe_api_key")
AIRDROP_ADMIN_SECRET = os.getenv("AIRDROP_ADMIN_SECRET")
url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

templates = Jinja2Templates(directory="templates")

def init_db():
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_results (url TEXT PRIMARY KEY, status TEXT, timestamp TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (google_id TEXT PRIMARY KEY, email TEXT, last_login TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (email TEXT PRIMARY KEY, url_found TEXT, scan_count INTEGER DEFAULT 0, wallet_address TEXT, tokens_sent INTEGER DEFAULT 0)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_events
                        (email TEXT NOT NULL, payload_hash TEXT NOT NULL, url_found TEXT NOT NULL,
                         first_scanned_at TEXT NOT NULL,
                         PRIMARY KEY (email, payload_hash))''')
    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = {row[1] for row in cursor.fetchall()}
    if "airdrop_eligible" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_eligible INTEGER DEFAULT 0")
    cursor.execute("UPDATE scans SET airdrop_eligible = 1 WHERE scan_count >= 5")
    conn.commit()
    conn.close()

init_db()

def record_unique_scan(email, url, wallet):
    normalized_payload = url.strip()
    payload_hash = hashlib.sha256(normalized_payload.encode("utf-8")).hexdigest()

    with sqlite3.connect('qr_cache.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (email, url_found, scan_count, wallet_address)
            VALUES (?, ?, 0, ?)
            ON CONFLICT(email) DO UPDATE SET
                wallet_address = COALESCE(excluded.wallet_address, scans.wallet_address)
        """, (email, normalized_payload, wallet))

        cursor.execute("SELECT url_found, scan_count FROM scans WHERE email = ?", (email,))
        previous_url, current_count = cursor.fetchone()

        cursor.execute("""
            INSERT OR IGNORE INTO scan_events (email, payload_hash, url_found, first_scanned_at)
            VALUES (?, ?, ?, ?)
        """, (email, payload_hash, normalized_payload, datetime.now().isoformat()))

        if cursor.rowcount == 0:
            return False

        # Existing rows may already have counted the last scanned payload before
        # scan_events existed. Backfill that event without giving an extra scan.
        previous_urls = [entry.strip() for entry in str(previous_url or "").split(",") if entry.strip()]
        if normalized_payload in previous_urls and current_count > 0:
            cursor.execute("""
                UPDATE scans
                SET wallet_address = COALESCE(?, wallet_address)
                WHERE email = ?
            """, (wallet, email))
            return False

        previous_urls.append(normalized_payload)
        updated_urls = ",".join(previous_urls)

        cursor.execute("""
            UPDATE scans
            SET scan_count = scan_count + 1,
                url_found = ?,
                wallet_address = COALESCE(?, wallet_address),
                airdrop_eligible = CASE WHEN scan_count + 1 >= 5 THEN 1 ELSE airdrop_eligible END
            WHERE email = ?
        """, (updated_urls, wallet, email))
        return True

def get_scan_count(email):
    with sqlite3.connect("qr_cache.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT scan_count FROM scans WHERE email = ?", (email,))
        result = cursor.fetchone()
        return result[0] if result else 0

def get_cached_result(target_url: str):
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    cursor.execute("SELECT status, timestamp FROM scan_results WHERE url = ?", (target_url,))
    row = cursor.fetchone()
    conn.close()
    if row:
        last_scan = datetime.fromisoformat(row[1])
        if datetime.now() - last_scan < timedelta(hours=24):
            return row[0]
    return None

def save_to_cache(target_url: str, status: str):
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO scan_results VALUES (?, ?, ?)", (target_url, status, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def check_url(target_url):
    payload = {
        "client" : {"clientId": "your_app" , "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url" : target_url}]
        }
    }
    response = requests.post(url, json=payload)
    return response.json()

def is_url_like(value):
    return bool(re.match(r"^https?://", value, re.IGNORECASE) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", value, re.IGNORECASE))

def normalize_url(target_url):
    trimmed = target_url.strip()
    if not re.match(r"^https?://", trimmed, re.IGNORECASE):
        return f"https://{trimmed}"
    return trimmed

def extract_urls(text):
    return re.findall(r"https?://[^\s<>'\"]+", text, flags=re.IGNORECASE)

def detect_payload(raw_payload):
    payload = raw_payload.strip()
    upper = payload.upper()

    if is_url_like(payload):
        return "URL", "Open website", normalize_url(payload)
    if upper.startswith("WIFI:"):
        return "Wi-Fi", "Join Wi-Fi network", payload
    if "BEGIN:VCARD" in upper:
        return "Contact card", "Import contact", payload
    if upper.startswith(("SMSTO:", "SMS:")):
        return "SMS", "Open prefilled text message", payload
    if upper.startswith("MAILTO:"):
        return "Email", "Open prefilled email", payload
    if upper.startswith(("SOLANA:", "BITCOIN:", "ETHEREUM:")):
        return "Crypto/payment", "Open wallet or payment request", payload
    if upper.startswith("BEGIN:VEVENT") or "BEGIN:VCALENDAR" in upper:
        return "Calendar", "Add calendar event", payload

    try:
        json.loads(payload)
        return "JSON/custom", "Run app-specific data flow", payload
    except ValueError:
        return "Plain text", "Display text payload", payload

def analyze_non_url_payload(raw_payload):
    payload_type, action, normalized = detect_payload(raw_payload)
    embedded_urls = extract_urls(normalized)
    score = 0
    status = "SAFE"
    threat_class = f"{payload_type}: {action}"

    if payload_type == "Wi-Fi":
        score = 25
        status = "CAUTION"
        if "T:WEP" in normalized.upper() or "T:NOPASS" in normalized.upper():
            score = 45
            threat_class = "Wi-Fi network with weak or open security"
        else:
            threat_class = "Wi-Fi join request: review network name before joining"
    elif payload_type in ("SMS", "Email"):
        score = 35
        status = "CAUTION"
        threat_class = f"{payload_type} action: review recipient and message before sending"
    elif payload_type == "Contact card":
        score = 20
        status = "CAUTION"
        threat_class = "Contact import: review names, phone numbers, and links before saving"
    elif payload_type == "Crypto/payment":
        score = 60
        status = "CAUTION"
        threat_class = "Wallet/payment request: verify destination before approving"
    elif payload_type == "Calendar":
        score = 20
        status = "CAUTION"
        threat_class = "Calendar event: review event details before adding"
    elif payload_type == "JSON/custom":
        score = 30
        status = "CAUTION"
        threat_class = "Custom app payload: inspect app-specific action before running"

    if embedded_urls:
        score = max(score, 45)
        status = "CAUTION"
        threat_class = f"{payload_type} containing embedded URL: inspect destination before action"

    risky_words = ("password", "seed", "recovery", "verify", "login", "wallet", "bank", "urgent")
    if any(word in normalized.lower() for word in risky_words):
        score = max(score, 55)
        status = "CAUTION"
        threat_class = f"{payload_type} includes sensitive or urgency language"

    return {
        "status": status,
        "score": str(score),
        "threat_class": threat_class,
        "source": "SafeScan Payload Analyzer",
        "normalized": normalized,
        "payload_type": payload_type
    }

def analyze_url_payload(raw_payload):
    normalized = normalize_url(raw_payload)
    parsed = urlparse(normalized)
    lower_url = normalized.lower()
    score = 0
    threat_class = "Safe Destination"

    cached_status = get_cached_result(normalized)
    if cached_status:
        return {
            "status": cached_status,
            "score": "95" if cached_status == "MALICIOUS" else "0",
            "threat_class": "Phishing/Malware Risk" if cached_status == "MALICIOUS" else "Safe Destination",
            "source": "Local Cache",
            "normalized": normalized,
            "payload_type": "URL"
        }

    safety_result = check_url(normalized)
    status = "MALICIOUS" if "matches" in safety_result else "SAFE"

    if parsed.scheme != "https":
        score += 20
        threat_class = "Non-HTTPS destination"
    if parsed.hostname and parsed.hostname.endswith((".top", ".zip", ".click", ".shop")):
        score += 20
        threat_class = "Higher-risk URL destination"
    if any(keyword in lower_url for keyword in ("download", ".apk", ".exe", ".dmg", ".pkg", ".zip")):
        score += 45
        threat_class = "Download or installer link: review before opening"
    if any(keyword in lower_url for keyword in ("verify", "login", "password", "wallet", "seed", "recovery")):
        score += 25
        threat_class = "Credential or wallet-themed URL"

    if status == "MALICIOUS":
        score = 95
        threat_class = "Phishing/Malware Risk"
    elif score >= 45:
        status = "CAUTION"
    else:
        score = 0

    save_to_cache(normalized, status)
    return {
        "status": status,
        "score": str(min(score, 95)),
        "threat_class": threat_class,
        "source": "SafeScan Engine",
        "normalized": normalized,
        "payload_type": "URL"
    }

def analyze_qr_payload(raw_payload):
    payload_type, _, normalized = detect_payload(raw_payload)
    if payload_type == "URL":
        return analyze_url_payload(normalized)
    return analyze_non_url_payload(normalized)

def decode_qr_image(image):
    image = ImageOps.exif_transpose(image)
    candidates = []

    def add_candidate(candidate):
        if candidate.mode not in ("RGB", "L"):
            candidate = candidate.convert("RGB")
        candidates.append(candidate)

    add_candidate(image)

    max_side = max(image.size)
    if max_side < 1400:
        scale = 1400 / max_side
        resized = image.resize(
            (int(image.width * scale), int(image.height * scale)),
            Image.Resampling.LANCZOS
        )
        add_candidate(resized)
    else:
        resized = image

    gray = ImageOps.grayscale(resized)
    add_candidate(gray)

    contrast = ImageOps.autocontrast(gray)
    add_candidate(contrast)

    sharpened = contrast.filter(ImageFilter.SHARPEN)
    add_candidate(sharpened)

    high_contrast = ImageEnhance.Contrast(sharpened).enhance(1.8)
    add_candidate(high_contrast)

    for threshold in (95, 125, 155):
        add_candidate(high_contrast.point(lambda pixel, limit=threshold: 255 if pixel > limit else 0))

    for candidate in candidates:
        for angle in (0, 90, 180, 270):
            rotated = candidate if angle == 0 else candidate.rotate(angle, expand=True)
            decoded = decode(rotated)
            if decoded:
                return decoded

    return []

qr_app = FastAPI()
qr_app.mount("/static", StaticFiles(directory="static"), name="static")

qr_app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

@qr_app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": False, "results_visible": False, "google_client_id": CLIENT_ID
    })

@qr_app.post("/search_qr_api", response_class=HTMLResponse)
async def scan_qr(
    request: Request,
    user_email: str = Form(...),
    wallet_address: str = Form(""),
    file: UploadFile = File(None),
    manual_url: str = Form(None)
):
    url_qr = None

    if manual_url and manual_url.strip():
        url_qr = manual_url.strip()
    elif file and file.filename:
        contents = await file.read()
        try:
            image = Image.open(io.BytesIO(contents))
            decoded_qr = decode_qr_image(image)
            if decoded_qr:
                url_qr = decoded_qr[0].data.decode("utf-8")
        except Exception:
            pass

    if not url_qr:
        return templates.TemplateResponse("index.html", {
            "request": request, "logged_in": True, "results_visible": True,
            "status": "ERROR", "url_found": "No QR code or valid URL detected.",
            "source": "Scanner", "score": "0", "threat_class": "N/A",
            "email": user_email, "scan_count": get_scan_count(user_email), "google_client_id": CLIENT_ID
        })

    analysis = analyze_qr_payload(url_qr)
    record_unique_scan(user_email, url_qr, wallet_address)

    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": True,
        "status": analysis["status"], "url_found": analysis["normalized"], "source": analysis["source"],
        "score": analysis["score"],
        "threat_class": analysis["threat_class"],
        "email": user_email, "scan_count": get_scan_count(user_email), "google_client_id": CLIENT_ID
    })

@qr_app.post("/auth/google", response_class=HTMLResponse)
@qr_app.get("/auth/google", response_class=HTMLResponse)
async def auth_google(request: Request, credential: str = Form(None)):
    if credential:
        try:
            idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), CLIENT_ID)
            user_email = idinfo['email']
        except ValueError:
            user_email = "error@invalid-token.com"
    else:
        user_email = "guest@demo.com"

    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": False,
        "email": user_email, "score": "0", "threat_class": "N/A",
        "scan_count": get_scan_count(user_email), "google_client_id": CLIENT_ID
    })

@qr_app.get("/trigger-airdrop-secret")
async def trigger_airdrop(
    secret: str = Query(None),
    x_airdrop_secret: str = Header(None)
):
    provided_secret = x_airdrop_secret or secret
    if not AIRDROP_ADMIN_SECRET:
        return {
            "status": "Blocked",
            "error": "AIRDROP_ADMIN_SECRET is not set on the server."
        }

    if provided_secret != AIRDROP_ADMIN_SECRET:
        return {
            "status": "Blocked",
            "error": "Invalid or missing airdrop admin secret."
        }

    try:
        result = await airdrop_sweep()
        return {
            "status": result.get("status", "ok"),
            "message": "Airdrop sweep executed.",
            "result": result
        }
    except Exception as e:
        return {
            "status": "Failed",
            "error": str(e) or repr(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(limit=3)
        }

def save_user_to_db(google_id, email):
    with sqlite3.connect("qr_cache.db") as conn:
        conn.execute("""
            INSERT INTO users (google_id, email, last_login)
            VALUES (?, ?, ?)
            ON CONFLICT(google_id) DO UPDATE SET
                email=excluded.email,
                last_login=excluded.last_login
        """, (google_id, email, datetime.now().isoformat()))



# print("Testing URL bad:")
# print(check_url("http://testsafebrowsing.appspot.com/s/malware.html"))

# print("Testing URL good:")
# print(check_url("https://google.com"))
