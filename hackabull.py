import requests
import json
import warnings
import io
import sqlite3
from datetime import datetime, timedelta
from PIL import Image
from pyzbar.pyzbar import decode

from fastapi import FastAPI, UploadFile, File, Request, Form
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
url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

templates = Jinja2Templates(directory="templates")

def init_db():
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_results (url TEXT PRIMARY KEY, status TEXT, timestamp TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (google_id TEXT PRIMARY KEY, email TEXT, last_login TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (email TEXT PRIMARY KEY, url_found TEXT, scan_count INTEGER DEFAULT 0, wallet_address TEXT, tokens_sent INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

init_db()

def record_unique_scan(email, target_url, wallet):
    target_url = target_url.strip()
    conn = sqlite3.connect('qr_cache.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT url_found, scan_count FROM scans WHERE email = ?", (email,))
    row = cursor.fetchone()
    
    if row:
        existing_urls = str(row[0]) if row[0] else ""
        current_count = int(row[1]) if row[1] else 0
        
        # Build clean list of previously scanned URLs
        scanned_list = [u.strip() for u in existing_urls.split(",") if u.strip()]
        
        if target_url not in scanned_list:
            # Completely new URL: Append and +1 the score
            scanned_list.append(target_url)
            updated_urls = ",".join(scanned_list)
            new_count = current_count + 1 
            
            cursor.execute("""
                UPDATE scans SET scan_count = ?, url_found = ?, wallet_address = ? WHERE email = ?
            """, (new_count, updated_urls, wallet, email))
        else:
            # Duplicate URL: Do not increment score, just update wallet
            cursor.execute("""
                UPDATE scans SET wallet_address = ? WHERE email = ?
            """, (wallet, email))
    else:
        # First scan ever
        cursor.execute("""
            INSERT INTO scans (email, url_found, scan_count, wallet_address)
            VALUES (?, ?, 1, ?)
        """, (email, target_url, wallet))
    
    conn.commit()
    conn.close()

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
            decoded_qr = decode(image)
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

    cached_status = get_cached_result(url_qr)
    if cached_status:
        record_unique_scan(user_email, url_qr, wallet_address)
        return templates.TemplateResponse("index.html", {
            "request": request, "logged_in": True, "results_visible": True,
            "status": cached_status, "url_found": url_qr, "source": "Local Cache",
            "score": "95" if cached_status == "MALICIOUS" else "0",
            "threat_class": "Phishing/Malware Risk" if cached_status == "MALICIOUS" else "Safe Destination",
            "email": user_email, "scan_count": get_scan_count(user_email), "google_client_id": CLIENT_ID
        })

    safety_result = check_url(url_qr)
    status = "MALICIOUS" if "matches" in safety_result else "SAFE"
    save_to_cache(url_qr, status)
    record_unique_scan(user_email, url_qr, wallet_address)
    
    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": True,
        "status": status, "url_found": url_qr, "source": "SafeScan Engine",
        "score": "95" if status == "MALICIOUS" else "0",  
        "threat_class": "Phishing/Malware Risk" if status == "MALICIOUS" else "Safe Destination", 
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
async def trigger_airdrop():
    try:
        await airdrop_sweep()
        return {"status": "Success", "message": "Airdrop sweep executed! Check Render logs."}
    except Exception as e:
        return {"status": "Failed", "error": str(e)}