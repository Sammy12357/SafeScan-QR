import requests
import json
import warnings
import io
import sqlite3
from datetime import datetime, timedelta
from PIL import Image
from pyzbar.pyzbar import decode

# Updated FastAPI imports
from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import FileResponse, HTMLResponse 
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

# Google Auth imports
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

import os
from dotenv import load_dotenv

from fastapi.staticfiles import StaticFiles 


templates = Jinja2Templates(directory="templates")


warnings.filterwarnings("ignore", category=ImportWarning)

load_dotenv()
CLIENT_ID = os.getenv("googe_client_id")
api_key = os.getenv("googe_api_key")
url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"


def init_db():
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    #qr database
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_results 
                      (url TEXT PRIMARY KEY, status TEXT, timestamp TEXT)''')
    #user database
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                        (google_id TEXT PRIMARY KEY, email TEXT, last_login TEXT)''')
    #unique scans tracker
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_scans 
                        (email TEXT, url TEXT, PRIMARY KEY (email, url))''')
    conn.commit()
    conn.close()

init_db()

# NEW: Helper functions for scoring
def record_unique_scan(email, url):
    with sqlite3.connect("qr_cache.db") as conn:
        try:
            conn.execute("INSERT INTO user_scans (email, url) VALUES (?, ?)", (email, url))
            return True # Successfully added new unique scan
        except sqlite3.IntegrityError:
            return False # Duplicate scan, ignored

def get_scan_count(email):
    with sqlite3.connect("qr_cache.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM user_scans WHERE email = ?", (email,))
        return cursor.fetchone()[0]



def get_cached_result(url: str):
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    cursor.execute("SELECT status, timestamp FROM scan_results WHERE url = ?", (url,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        # Check if the result is older than 24 hours (Safety data expires!)
        last_scan = datetime.fromisoformat(row[1])
        if datetime.now() - last_scan < timedelta(hours=24):
            return row[0]
    return None

def save_to_cache(url: str, status: str):
    conn = sqlite3.connect("qr_cache.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO scan_results VALUES (?, ?, ?)", 
                   (url, status, datetime.now().isoformat()))
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
    CORSMiddleware,
    allow_origins=["*"],  # Allows any website to call your API (fine for local testing)
    allow_methods=["*"],
    allow_headers=["*"],
)

@qr_app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "logged_in": False,
        "results_visible": False,
        "google_client_id": CLIENT_ID  # <-- Add this!
    })

@qr_app.post("/search_qr_api", response_class=HTMLResponse)
async def scan_qr(request: Request, file: UploadFile = File(...)):
    # 1. Read the image file from the HTML form
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))

    # 2. Use ZBar to find the QR code
    decoded_qr = decode(image)

    # Error Handle: If no QR is found, show the page with an error message
    if not decoded_qr:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "logged_in": True,
            "results_visible": True,
            "status": "ERROR",
            "url_found": "No QR code detected in the image.",
            "source": "Local Scanner"
        })
    
    # 3. Extract the URL from the QR code
    url_qr = decoded_qr[0].data.decode("utf-8")

    # 4. Check Cache First (to save API credits and speed)
    cached_status = get_cached_result(url_qr)
    if cached_status:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "logged_in": True,
            "results_visible": True,
            "status": cached_status,
            "url_found": url_qr,
            "source": "Local Cache"
        })

    # 5. Cache Miss - Call Google Safe Browsing
    safety_result = check_url(url_qr)
    status = "MALICIOUS" if "matches" in safety_result else "SAFE"
    
    # 6. Save result to cache
    save_to_cache(url_qr, status)
    
    # 7. Record scan and get new score
    user_email = "restreposamuel2004@gmail.com"
    record_unique_scan(user_email, url_qr)
    current_scans = get_scan_count(user_email)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "logged_in": True,
        "results_visible": True,
        "status": status,
        "url_found": url_qr,
        "source": "SafeScan Engine",
        "score": "95" if status == "MALICIOUS" else "0",  
        "threat_class": "Phishing/Malware Risk" if status == "MALICIOUS" else "Safe Destination", 
        "email": user_email,
        "scan_count": current_scans, # Pass updated score to HTML
        "google_client_id": CLIENT_ID
    })
    

# Replace your existing auth_google functions with this:

@qr_app.post("/auth/google", response_class=HTMLResponse)
@qr_app.post("/auth/google/", response_class=HTMLResponse)
@qr_app.get("/auth/google", response_class=HTMLResponse)
@qr_app.get("/auth/google/", response_class=HTMLResponse)
async def auth_google(request: Request, credential: str = Form(None)):
    
    # 1. Decode the real email from Google's token
    if credential:
        try:
            idinfo = id_token.verify_oauth2_token(
                credential, google_requests.Request(), CLIENT_ID
            )
            user_email = idinfo['email']
        except ValueError:
            user_email = "error@invalid-token.com" # Failsafe
    else:
        user_email = "guest@demo.com" # Failsafe for direct GET requests
        
    # 2. Fetch the real score for this specific user
    current_scans = get_scan_count(user_email) 
    
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "logged_in": True, 
        "results_visible": False, 
        "email": user_email,          # <--- Dynamically injected here
        "score": "0",             
        "threat_class": "N/A",
        "scan_count": current_scans,  # <--- Dynamic scan count
        "google_client_id": CLIENT_ID
    })

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




