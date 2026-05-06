import requests
import json
import warnings
import io
import sqlite3
import hashlib
import traceback
import re
import asyncio
import base64
from urllib.parse import urlparse, parse_qsl
from datetime import datetime, timedelta
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
from pyzbar.pyzbar import decode

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query, Body
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

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID") or os.getenv("googe_client_id")
api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("googe_api_key")
AIRDROP_ADMIN_SECRET = os.getenv("AIRDROP_ADMIN_SECRET")
safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() in ("1", "true", "yes", "on")
HIGH_RISK_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"}
URL_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}
MALICIOUS_CONTRACT_BLOCKLIST = {
    "11111111111111111111111111111111",
    "drainwallet111111111111111111111111111111",
}

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

def mock_analysis_response(target_url):
    normalized = normalize_url(target_url)
    signals = [
        signal("Domain Age", "8 days old", "high", "Domain registered less than 30 days ago, a common phishing indicator.", False),
        signal("VirusTotal Reputation", "12/90 engines flagged", "high", "Multiple reputation engines flagged this destination as unsafe.", False),
        signal("Redirect Chain", "2 redirect hops detected", "medium", "The QR destination redirects before reaching the final landing page.", False),
        signal("URL Shortener", "Shortener found in chain", "medium", "Shortened URLs can hide the true destination from users.", False),
        signal("TLD Risk", "Non-standard TLD .xyz", "low", "The domain uses a TLD that appears frequently in disposable campaigns.", False),
    ]
    verdict = "This QR code shows multiple high-risk signals, including a newly registered domain and reputation engine detections. Treat it as a likely phishing or wallet-drain attempt unless you can independently verify the sender."
    return {
        "url": normalized,
        "overallRisk": "high",
        "confidenceScore": 91,
        "verdict": verdict,
        "signals": signals,
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_url_reputation(target_url):
    if not api_key:
        return {
            "provider": "Google Safe Browsing",
            "status": "UNCONFIGURED",
            "matches": [],
            "detail": "Set GOOGLE_SAFE_BROWSING_API_KEY to enable live reputation checks."
        }

    payload = {
        "client" : {"clientId": "safescan-qr" , "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url" : target_url}]
        }
    }
    try:
        response = requests.post(safe_browsing_url, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as exc:
        return {
            "provider": "Google Safe Browsing",
            "status": "ERROR",
            "matches": [],
            "detail": f"Reputation lookup failed: {type(exc).__name__}"
        }

    matches = result.get("matches", [])
    return {
        "provider": "Google Safe Browsing",
        "status": "MALICIOUS" if matches else "CLEAR",
        "matches": [match.get("threatType", "UNKNOWN_THREAT") for match in matches],
        "detail": "Known unsafe URL match found." if matches else "No known unsafe URL match returned."
    }

def google_reputation_signal(target_url):
    reputation = check_url_reputation(target_url)
    if reputation["status"] == "MALICIOUS":
        result = ", ".join(reputation["matches"]) or "Unsafe match"
        return signal("Google Safe Browsing", result, "high", "Google Safe Browsing returned a known unsafe threat match.", False)
    if reputation["status"] == "CLEAR":
        return signal("Google Safe Browsing", "No matches", "low", "Google Safe Browsing did not return a known unsafe match.", True)
    return signal("Google Safe Browsing", reputation["status"], "low", reputation["detail"], True)

def virustotal_url_id(target_url):
    encoded = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")

def virustotal_reputation_signal(target_url):
    if not VIRUSTOTAL_API_KEY:
        return signal("VirusTotal Reputation", "Not configured", "low", "Set VIRUSTOTAL_API_KEY to enable VirusTotal v3 reputation checks.", True)

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = virustotal_url_id(target_url)
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        if response.status_code == 404:
            scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url}, timeout=8)
            scan_response.raise_for_status()
            return signal("VirusTotal Reputation", "Scan submitted", "low", "VirusTotal did not have a cached verdict, so the URL was submitted for analysis.", True)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        return signal("VirusTotal Reputation", "Lookup failed", "low", f"VirusTotal lookup failed: {type(exc).__name__}", True)

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(value or 0) for value in stats.values()) or 90
    severity = "high" if flagged else "low"
    return signal(
        "VirusTotal Reputation",
        f"{flagged}/{total} engines flagged",
        severity,
        "VirusTotal engines flagged this URL." if flagged else "VirusTotal did not report malicious or suspicious engine detections.",
        flagged == 0
    )

def inspect_redirects(target_url):
    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True, stream=True)
        response.close()
    except requests.RequestException as exc:
        return {
            "status": "ERROR",
            "count": 0,
            "final_url": target_url,
            "detail": f"Redirect inspection failed: {type(exc).__name__}"
        }

    return {
        "status": "OK",
        "count": len(response.history),
        "final_url": response.url,
        "detail": "Redirect chain inspected."
    }

def trace_redirect_chain(target_url):
    try:
        session = requests.Session()
        session.max_redirects = 10
        response = session.get(target_url, timeout=6, allow_redirects=True, stream=True)
        response.close()
    except requests.TooManyRedirects:
        return {
            "signal": signal("Redirect Chain", "More than 10 redirects", "high", "The URL exceeded the 10-hop redirect limit.", False),
            "redirectChain": []
        }
    except requests.RequestException as exc:
        return {
            "signal": signal("Redirect Chain", "Inspection failed", "low", f"Redirect inspection failed: {type(exc).__name__}", True),
            "redirectChain": []
        }

    all_responses = list(response.history) + [response]
    original_domain = urlparse(target_url).hostname or ""
    chain = []
    domain_changed = False
    has_shortener = False
    for item in all_responses:
        item_url = item.url
        domain = urlparse(item_url).hostname or ""
        changed = bool(original_domain and domain and domain != original_domain)
        domain_changed = domain_changed or changed
        has_shortener = has_shortener or domain.lower().removeprefix("www.") in URL_SHORTENERS
        chain.append({"url": item_url, "domain": domain, "statusCode": item.status_code, "domainChanged": changed})

    hop_count = max(0, len(chain) - 1)
    suspicious = hop_count > 2 or domain_changed or has_shortener
    severity = "high" if suspicious else ("medium" if hop_count else "low")
    details = []
    if hop_count > 2:
        details.append("more than 2 redirect hops")
    if domain_changed:
        details.append("final or intermediate domain differs from the original")
    if has_shortener:
        details.append("known URL shortener appears in the chain")
    description = "Redirect chain is simple." if not details else "Suspicious redirect pattern: " + ", ".join(details) + "."
    return {
        "signal": signal("Redirect Chain", f"{hop_count} hop(s)", severity, description, not suspicious),
        "redirectChain": chain
    }

def parse_rdap_creation_date(events):
    for event in events or []:
        if event.get("eventAction") in ("registration", "domain registration", "creation"):
            date_value = event.get("eventDate")
            if date_value:
                try:
                    return datetime.fromisoformat(date_value.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    return None
    return None

def check_domain_intelligence(target_url):
    normalized = normalize_url(target_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return signal("Domain Intelligence", "No domain", "medium", "No valid domain could be extracted from the payload.", False)

    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    tld_signal = None
    if tld in HIGH_RISK_TLDS:
        tld_signal = signal("TLD Risk", f"High-risk TLD {tld}", "low", f"The domain uses {tld}, which appears often in disposable phishing campaigns.", False)

    try:
        response = requests.get(f"https://rdap.org/domain/{hostname}", timeout=6)
        response.raise_for_status()
        rdap = response.json()
        created_at = parse_rdap_creation_date(rdap.get("events", []))
        registrar = rdap.get("registrar") or rdap.get("entities", [{}])[0].get("handle", "Unknown")
    except (requests.RequestException, ValueError, KeyError, IndexError):
        base = signal("Domain Age", "Lookup unavailable", "low", "Domain registration lookup could not be completed.", True)
        return [base, tld_signal] if tld_signal else [base]

    if not created_at:
        base = signal("Domain Age", "Unknown", "low", f"WHOIS/RDAP lookup completed, but no creation date was returned. Registrar: {registrar}.", True)
        return [base, tld_signal] if tld_signal else [base]

    age_days = max(0, (datetime.utcnow() - created_at).days)
    if age_days < 30:
        severity = "high"
        passed = False
    elif age_days <= 90:
        severity = "medium"
        passed = False
    else:
        severity = "low"
        passed = True
    base = signal("Domain Age", f"{age_days} days old", severity, f"Domain age from RDAP. Registrar: {registrar}.", passed)
    return [base, tld_signal] if tld_signal else [base]

def check_crypto_pattern_signals(target_url):
    parsed = urlparse(target_url)
    haystack_parts = [target_url, parsed.query, parsed.fragment]
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        haystack_parts.append(value)
    haystack = " ".join(haystack_parts)
    lower = haystack.lower()
    found = []

    solana_patterns = ("transferchecked", "drainwallet", "sweeptokens", "sign-message", "signmessage")
    for pattern in solana_patterns:
        if pattern in lower:
            found.append(signal("Crypto Pattern", pattern, "high", f"Found {pattern}, a wallet-drain or token-transfer signature pattern.", False))

    if "approve" in lower and ("uint256" in lower or "ffffffffffffffff" in lower or "max" in lower):
        found.append(signal("Ethereum Approval Pattern", "approve max uint256", "high", "The payload appears to request a maximum token approval.", False))

    base58_pattern = r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![A-Za-z0-9])"
    base58_hits = re.findall(base58_pattern, parsed.query + " " + parsed.fragment)
    if base58_hits:
        found.append(signal("Solana Address Placement", f"{len(base58_hits)} address-like value(s)", "high", "Base58 wallet addresses appear inside query parameters or hash fragments.", False))

    for blocked in MALICIOUS_CONTRACT_BLOCKLIST:
        if blocked.lower() in lower:
            found.append(signal("Known Malicious Contract", blocked, "high", "The payload contains an address from the SafeScan MVP blocklist.", False))

    if not found:
        found.append(signal("Crypto Pattern", "No wallet-drain pattern found", "low", "No known Solana/Ethereum wallet-drain signature patterns were detected.", True))
    return found

def generate_ai_verdict(signals):
    score = score_from_signals(signals)
    overall_risk = risk_from_score(score)
    high_checks = [item["check"] for item in signals if item["severity"] == "high"]
    medium_checks = [item["check"] for item in signals if item["severity"] == "medium"]

    if high_checks:
        verdict = f"This QR code shows high-risk indicators in {', '.join(high_checks[:3])}. Do not continue unless you can independently verify the destination and sender."
    elif medium_checks:
        verdict = f"This QR code looks suspicious because {', '.join(medium_checks[:3])} need review. Continue only after confirming the domain, redirect path, and wallet action."
    else:
        verdict = "SafeScan did not find strong phishing or wallet-drain indicators in this QR payload. Still verify the destination before connecting a wallet or sending funds."

    fallback = {"overallRisk": overall_risk, "confidenceScore": score, "verdict": verdict}
    analyst_prompt = (
        "You are a QR security analyst. Review these SafeScan signal objects and return JSON only with "
        "overallRisk as safe, suspicious, or high; confidenceScore from 0-100; and verdict as a two-sentence "
        "plain-English explanation. Weight high severity at 40 points each capped at 80, medium at 15, low at 5, "
        "and push new-domain + redirect + wallet-pattern combinations to 90+.\n\n"
        f"Signals JSON:\n{json.dumps(signals)}"
    )

    try:
        if ANTHROPIC_API_KEY:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
                    "max_tokens": 300,
                    "system": "Return structured JSON only. Do not include markdown.",
                    "messages": [{"role": "user", "content": analyst_prompt}]
                },
                timeout=10
            )
            response.raise_for_status()
            content = response.json()["content"][0]["text"]
            return json.loads(content)
        if OPENAI_API_KEY:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "content-type": "application/json"},
                json={
                    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": "You are a QR security analyst. Return structured JSON only."},
                        {"role": "user", "content": analyst_prompt}
                    ]
                },
                timeout=10
            )
            response.raise_for_status()
            return json.loads(response.json()["choices"][0]["message"]["content"])
    except (requests.RequestException, KeyError, IndexError, ValueError, json.JSONDecodeError):
        return fallback

    return fallback

async def analyze_full_pipeline(target_url):
    normalized = normalize_url(target_url)
    if MOCK_MODE:
        return mock_analysis_response(normalized)

    domain_task = asyncio.to_thread(check_domain_intelligence, normalized)
    redirect_task = asyncio.to_thread(trace_redirect_chain, normalized)
    reputation_task = asyncio.to_thread(check_reputation_signals, normalized)
    crypto_task = asyncio.to_thread(check_crypto_pattern_signals, normalized)
    domain_result, redirect_result, reputation_signals, crypto_signals = await asyncio.gather(domain_task, redirect_task, reputation_task, crypto_task)

    signals = []
    signals.extend(domain_result if isinstance(domain_result, list) else [domain_result])
    signals.append(redirect_result["signal"])
    signals.extend(reputation_signals)
    signals.extend(crypto_signals)
    signals = sorted(signals, key=severity_rank)
    ai_verdict = generate_ai_verdict(signals)

    return {
        "url": normalized,
        "overallRisk": ai_verdict["overallRisk"],
        "confidenceScore": ai_verdict["confidenceScore"],
        "verdict": ai_verdict["verdict"],
        "signals": signals,
        "redirectChain": redirect_result.get("redirectChain", []),
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_reputation_signals(target_url):
    return [google_reputation_signal(target_url), virustotal_reputation_signal(target_url)]

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
    reasons = []

    if payload_type == "Wi-Fi":
        score = 25
        status = "CAUTION"
        if "T:WEP" in normalized.upper() or "T:NOPASS" in normalized.upper():
            score = 45
            threat_class = "Wi-Fi network with weak or open security"
            reasons.append(risk_reason("Weak Wi-Fi security", "medium", "The QR can join a WEP or open network. Confirm the network is trusted before joining."))
        else:
            threat_class = "Wi-Fi join request: review network name before joining"
            reasons.append(risk_reason("Wi-Fi join request", "low", "The QR changes device network state, so the SSID and security type should be reviewed."))
    elif payload_type in ("SMS", "Email"):
        score = 35
        status = "CAUTION"
        threat_class = f"{payload_type} action: review recipient and message before sending"
        reasons.append(risk_reason(f"{payload_type} action", "medium", "The QR can open a prefilled message. Review the recipient and body before sending."))
    elif payload_type == "Contact card":
        score = 20
        status = "CAUTION"
        threat_class = "Contact import: review names, phone numbers, and links before saving"
        reasons.append(risk_reason("Contact import", "low", "The QR can add contact data to your device. Review names, phone numbers, and links."))
    elif payload_type == "Crypto/payment":
        score = 60
        status = "CAUTION"
        threat_class = "Wallet/payment request: verify destination before approving"
        reasons.append(risk_reason("Wallet or payment request", "high", "The QR can launch a crypto wallet or payment flow. Verify the destination before approving."))
    elif payload_type == "Calendar":
        score = 20
        status = "CAUTION"
        threat_class = "Calendar event: review event details before adding"
        reasons.append(risk_reason("Calendar write request", "low", "The QR can add an event to the calendar. Review the organizer, links, and date."))
    elif payload_type == "JSON/custom":
        score = 30
        status = "CAUTION"
        threat_class = "Custom app payload: inspect app-specific action before running"
        reasons.append(risk_reason("Custom app payload", "medium", "The QR contains structured data that another app may interpret."))

    if embedded_urls:
        score = max(score, 45)
        status = "CAUTION"
        threat_class = f"{payload_type} containing embedded URL: inspect destination before action"
        reasons.append(risk_reason("Embedded URL detected", "medium", "The payload contains a link hidden inside another QR action."))

    risky_words = ("password", "seed", "recovery", "verify", "login", "wallet", "bank", "urgent")
    if any(word in normalized.lower() for word in risky_words):
        score = max(score, 55)
        status = "CAUTION"
        threat_class = f"{payload_type} includes sensitive or urgency language"
        reasons.append(risk_reason("Sensitive language", "medium", "The payload references wallet, password, login, recovery, or urgency wording."))

    if not reasons:
        reasons.append(risk_reason("No risky payload pattern detected", "low", "SafeScan did not find wallet-drainer, credential, redirect, or suspicious QR action indicators."))

    return {
        "status": status,
        "score": str(score),
        "threat_class": threat_class,
        "source": "SafeScan Payload Analyzer",
        "normalized": normalized,
        "payload_type": payload_type,
        "reputation": {"provider": "SafeScan Payload Analyzer", "status": "NOT_APPLICABLE", "matches": [], "detail": "Reputation lookup only runs for URL payloads."},
        "reasons": reasons
    }

def analyze_url_payload(raw_payload):
    normalized = normalize_url(raw_payload)
    parsed = urlparse(normalized)
    lower_url = normalized.lower()
    score = 0
    threat_class = "Safe Destination"
    reasons = []

    cached_status = get_cached_result(normalized)
    if cached_status:
        return {
            "status": cached_status,
            "score": "95" if cached_status == "MALICIOUS" else "0",
            "threat_class": "Phishing/Malware Risk" if cached_status == "MALICIOUS" else "Safe Destination",
            "source": "Local Cache",
            "normalized": normalized,
            "payload_type": "URL",
            "reputation": {"provider": "Local Cache", "status": cached_status, "matches": [], "detail": "Cached verdict from the last 24 hours."},
            "reasons": [risk_reason("Cached reputation verdict", "high" if cached_status == "MALICIOUS" else "low", "This URL was recently scanned and reused from local cache.")]
        }

    reputation = check_url_reputation(normalized)
    redirect_result = inspect_redirects(normalized)
    status = "MALICIOUS" if reputation["status"] == "MALICIOUS" else "SAFE"

    if parsed.scheme != "https":
        score += 20
        threat_class = "Non-HTTPS destination"
        reasons.append(risk_reason("Non-HTTPS destination", "medium", "The decoded URL does not use HTTPS, which makes spoofing and interception riskier."))
    if parsed.hostname and parsed.hostname.endswith((".top", ".zip", ".click", ".shop")):
        score += 20
        threat_class = "Higher-risk URL destination"
        reasons.append(risk_reason("Higher-risk top-level domain", "medium", "The domain uses a TLD often seen in disposable phishing or scam campaigns."))
    if any(keyword in lower_url for keyword in ("download", ".apk", ".exe", ".dmg", ".pkg", ".zip")):
        score += 45
        threat_class = "Download or installer link: review before opening"
        reasons.append(risk_reason("Download or installer link", "high", "The URL appears to trigger a download or installer path."))
    if any(keyword in lower_url for keyword in ("verify", "login", "password", "wallet", "seed", "recovery")):
        score += 25
        threat_class = "Credential or wallet-themed URL"
        reasons.append(risk_reason("Credential or wallet wording", "high", "The URL contains login, seed, recovery, password, verify, or wallet language."))
    if any(keyword in lower_url for keyword in ("drain", "drainer", "approve", "approval", "permit", "signature", "sign-message", "airdrop", "claim")):
        score += 35
        threat_class = "Wallet drain signature pattern"
        reasons.append(risk_reason("Wallet drain signature pattern", "high", "The URL uses claim, approve, signature, permit, or drainer language often seen in wallet-draining flows."))
    if redirect_result["count"] > 0:
        score += min(30, redirect_result["count"] * 15)
        threat_class = "Redirecting destination"
        reasons.append(risk_reason("Redirects detected", "medium", f"The URL redirects {redirect_result['count']} time(s) before landing on {redirect_result['final_url']}."))
    elif redirect_result["status"] == "ERROR":
        reasons.append(risk_reason("Redirect inspection unavailable", "low", redirect_result["detail"]))

    if status == "MALICIOUS":
        score = 95
        threat_class = "Phishing/Malware Risk"
        reasons.insert(0, risk_reason("Google Safe Browsing match", "high", "Live reputation lookup returned a known unsafe threat match."))
    elif score >= 45:
        status = "CAUTION"
    else:
        score = 0

    if reputation["status"] == "CLEAR":
        reasons.append(risk_reason("Reputation lookup clear", "low", "Google Safe Browsing did not return a known unsafe match for this URL."))
    elif reputation["status"] in ("UNCONFIGURED", "ERROR"):
        reasons.append(risk_reason("Reputation lookup unavailable", "low", reputation["detail"]))
    if not reasons:
        reasons.append(risk_reason("No suspicious URL pattern detected", "low", "SafeScan did not find redirect, wallet-drainer, credential, or high-risk URL indicators."))

    save_to_cache(normalized, status)
    return {
        "status": status,
        "score": str(min(score, 95)),
        "threat_class": threat_class,
        "source": "SafeScan Engine",
        "normalized": normalized,
        "payload_type": "URL",
        "reputation": reputation,
        "reasons": reasons
    }

def analyze_qr_payload(raw_payload):
    payload_type, _, normalized = detect_payload(raw_payload)
    if payload_type == "URL":
        return analyze_url_payload(normalized)
    return analyze_non_url_payload(normalized)

def pipeline_response_to_template_analysis(pipeline_response):
    overall_risk = pipeline_response["overallRisk"]
    signals = pipeline_response.get("signals", [])
    first_high = next((item for item in signals if item["severity"] == "high"), None)
    first_signal = first_high or (signals[0] if signals else None)
    return {
        "status": status_from_risk(overall_risk),
        "score": str(pipeline_response["confidenceScore"]),
        "threat_class": first_signal["check"] if first_signal else "SafeScan Risk Engine",
        "source": "SafeScan Core Risk Engine",
        "normalized": pipeline_response["url"],
        "payload_type": "URL",
        "overallRisk": overall_risk,
        "verdict": pipeline_response["verdict"],
        "reputation": {"provider": "SafeScan Core Risk Engine", "status": overall_risk.upper(), "matches": [], "detail": pipeline_response["verdict"]},
        "reasons": signals
    }

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

@qr_app.post("/api/analyze")
async def api_analyze(payload: dict = Body(...)):
    target_url = (payload.get("url") or "").strip()
    if not target_url:
        return JSONResponse({"error": "url is required"}, status_code=400)
    return await analyze_full_pipeline(target_url)

@qr_app.post("/api/check-reputation")
async def api_check_reputation(payload: dict = Body(...)):
    target_url = (payload.get("url") or "").strip()
    if not target_url:
        return JSONResponse({"error": "url is required"}, status_code=400)
    normalized = normalize_url(target_url)
    google_task = asyncio.to_thread(google_reputation_signal, normalized)
    virustotal_task = asyncio.to_thread(virustotal_reputation_signal, normalized)
    results = await asyncio.gather(google_task, virustotal_task)
    return {"url": normalized, "signals": list(results), "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.post("/api/trace-redirects")
async def api_trace_redirects(payload: dict = Body(...)):
    target_url = (payload.get("url") or "").strip()
    if not target_url:
        return JSONResponse({"error": "url is required"}, status_code=400)
    normalized = normalize_url(target_url)
    result = await asyncio.to_thread(trace_redirect_chain, normalized)
    return {"url": normalized, **result, "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.post("/api/check-domain")
async def api_check_domain(payload: dict = Body(...)):
    target_url = (payload.get("url") or "").strip()
    if not target_url:
        return JSONResponse({"error": "url is required"}, status_code=400)
    normalized = normalize_url(target_url)
    signals = await asyncio.to_thread(check_domain_intelligence, normalized)
    return {"url": normalized, "signals": signals, "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.post("/api/check-crypto-patterns")
async def api_check_crypto_patterns(payload: dict = Body(...)):
    target_url = (payload.get("url") or "").strip()
    if not target_url:
        return JSONResponse({"error": "url is required"}, status_code=400)
    normalized = normalize_url(target_url)
    signals = await asyncio.to_thread(check_crypto_pattern_signals, normalized)
    return {"url": normalized, "signals": signals, "scannedAt": datetime.utcnow().isoformat() + "Z"}

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
            "overall_risk": "suspicious",
            "verdict_summary": "SafeScan could not decode a QR payload from this image.",
            "reputation": {"provider": "Scanner", "status": "ERROR", "matches": [], "detail": "No decodable payload was found."},
            "risk_reasons": [risk_reason("No QR payload decoded", "medium", "Upload a clearer QR image or paste the destination manually.")],
            "email": user_email, "scan_count": get_scan_count(user_email), "google_client_id": CLIENT_ID
        })

    payload_type, _, normalized_payload = detect_payload(url_qr)
    if payload_type == "URL":
        pipeline_response = await analyze_full_pipeline(normalized_payload)
        analysis = pipeline_response_to_template_analysis(pipeline_response)
    else:
        analysis = analyze_qr_payload(url_qr)
    record_unique_scan(user_email, url_qr, wallet_address)

    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": True,
        "status": analysis["status"], "url_found": analysis["normalized"], "source": analysis["source"],
        "score": analysis["score"],
        "threat_class": analysis["threat_class"],
        "overall_risk": analysis.get("overallRisk", analysis["status"].lower()),
        "verdict_summary": analysis.get("verdict", analysis["threat_class"]),
        "reputation": analysis.get("reputation"),
        "risk_reasons": analysis.get("reasons", []),
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
