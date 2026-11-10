"""Local PhishTank feed snapshots for private, exact-URL phishing lookups.

The feed is never queried with a customer's URL. A background refresh writes a
new SQLite snapshot and atomically replaces the old one on persistent storage.
"""

import asyncio
import csv
import fcntl
import gzip
import io
import os
import re
import sqlite3
import tempfile
import time
from contextlib import closing
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from db import database_path
from .scoring import signal


FEED_NAME = "phishtank-online-valid.db"
MAX_FEED_AGE_SECONDS = 2 * 60 * 60
REFRESH_INTERVAL_SECONDS = 60 * 60
MAX_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 96 * 1024 * 1024
MAX_FEED_ROWS = 500_000
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_ALLOWED_DOWNLOAD_HOSTS = {"data.phishtank.com", "cdn.phishtank.com"}


def _flag_enabled(name):
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _app_key():
    key = os.getenv("PHISHTANK_APP_KEY", "").strip()
    return key if _KEY_PATTERN.fullmatch(key) else ""


def _enabled():
    return _flag_enabled("SAFESCAN_PHISHTANK_TERMS_CONFIRMED") and bool(_app_key())


def _feed_path():
    data_dir = os.getenv("DATA_DIR") or os.path.dirname(os.path.abspath(database_path()))
    return os.path.join(os.path.abspath(data_dir), FEED_NAME)


def canonical_feed_url(value):
    """Normalize only URL parts that cannot change the destination's meaning."""
    if not isinstance(value, str) or len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError):
        return None
    if scheme not in {"http", "https"} or not host or "@" in parsed.netloc:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def feed_status(now=None):
    """Report local snapshot freshness, never provider availability or a key."""
    if not _flag_enabled("SAFESCAN_PHISHTANK_TERMS_CONFIRMED"):
        return {"state": "terms_not_confirmed"}
    if not _app_key():
        return {"state": "app_key_missing"}
    path = _feed_path()
    if not os.path.isfile(path):
        return {"state": "missing"}
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)) as conn:
            row = conn.execute("SELECT fetched_at, entry_count FROM metadata LIMIT 1").fetchone()
        if not row or int(row[1]) < 1:
            return {"state": "invalid"}
        age = float(now if now is not None else time.time()) - float(row[0])
        if age < -300:
            return {"state": "invalid"}
        return {"state": "fresh" if age <= MAX_FEED_AGE_SECONDS else "stale", "ageSeconds": max(0, int(age))}
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return {"state": "invalid"}


def phishtank_signal(target_url):
    status = feed_status()
    state = status["state"]
    if state != "fresh":
        finding = signal("PhishTank", f"Unverified ({state.replace('_', ' ')})", "medium",
                         "The local verified-phishing feed is unavailable or older than two hours.", False)
        finding["verified"] = False
        return finding
    canonical = canonical_feed_url(target_url)
    if not canonical:
        finding = signal("PhishTank", "Unverified (invalid URL)", "medium",
                         "The URL could not be matched against the local feed.", False)
        finding["verified"] = False
        return finding
    try:
        with closing(sqlite3.connect(f"file:{_feed_path()}?mode=ro", uri=True, timeout=2)) as conn:
            hit = conn.execute("SELECT 1 FROM urls WHERE url = ?", (canonical,)).fetchone() is not None
    except (OSError, sqlite3.Error):
        finding = signal("PhishTank", "Unverified (feed read failed)", "medium",
                         "The local phishing feed could not be read.", False)
        finding["verified"] = False
        return finding
    if hit:
        finding = signal("PhishTank", "Verified active phishing URL", "high",
                         "This exact URL appears in PhishTank's verified online phishing feed.", False)
    else:
        finding = signal("PhishTank", "No known match", "low",
                         "This exact URL is not in the current verified online phishing feed; absence is not proof of safety.", True)
    finding["verified"] = True
    return finding


def _download_feed(key):
    url = f"https://data.phishtank.com/data/{key}/online-valid.csv.gz"
    headers = {"User-Agent": "SafeScanQR/1.0 (PhishTank feed client)", "Accept": "application/gzip"}
    with requests.Session() as session:
        # The application key is in the request path; never send it through an
        # ambient HTTP(S)_PROXY from the process environment.
        session.trust_env = False
        for _ in range(3):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
                raise ValueError("PhishTank feed redirected outside its approved hosts")
            response = session.get(url, headers=headers, timeout=(5, 30), stream=True, allow_redirects=False)
            try:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location", "")
                    if not location:
                        raise ValueError("PhishTank feed redirect has no destination")
                    url = urljoin(url, location)
                    continue
                if response.status_code != 200:
                    response.raise_for_status()
                    raise ValueError("PhishTank feed returned an unexpected status")
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_COMPRESSED_BYTES:
                    raise ValueError("PhishTank feed exceeds compressed size limit")
                compressed = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    compressed.extend(chunk)
                    if len(compressed) > MAX_COMPRESSED_BYTES:
                        raise ValueError("PhishTank feed exceeds compressed size limit")
                with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as archive:
                    uncompressed = archive.read(MAX_UNCOMPRESSED_BYTES + 1)
                if len(uncompressed) > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("PhishTank feed exceeds expanded size limit")
                return uncompressed
            finally:
                response.close()
    raise ValueError("PhishTank feed exceeded redirect limit")


def _write_snapshot(csv_bytes, path, fetched_at):
    try:
        reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig"), newline=""))
    except UnicodeError as exc:
        raise ValueError("PhishTank feed is not UTF-8 CSV") from exc
    if not reader.fieldnames or not {"url", "verified", "online"}.issubset(set(reader.fieldnames)):
        raise ValueError("PhishTank feed columns are incomplete")

    fd, temporary_path = tempfile.mkstemp(prefix=".phishtank-", suffix=".db", dir=os.path.dirname(path))
    os.close(fd)
    try:
        with closing(sqlite3.connect(temporary_path, timeout=30)) as conn:
            conn.execute("CREATE TABLE urls (url TEXT PRIMARY KEY)")
            conn.execute("CREATE TABLE metadata (fetched_at REAL NOT NULL, entry_count INTEGER NOT NULL)")
            batch = []
            rows_seen = 0
            for row in reader:
                rows_seen += 1
                if rows_seen > MAX_FEED_ROWS:
                    raise ValueError("PhishTank feed exceeds row limit")
                if row.get("verified", "").strip().lower() != "yes" or row.get("online", "").strip().lower() != "yes":
                    continue
                canonical = canonical_feed_url(row.get("url"))
                if canonical:
                    batch.append((canonical,))
                if len(batch) >= 1000:
                    conn.executemany("INSERT OR IGNORE INTO urls(url) VALUES (?)", batch)
                    batch.clear()
            if batch:
                conn.executemany("INSERT OR IGNORE INTO urls(url) VALUES (?)", batch)
            count = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            if count < 1:
                raise ValueError("PhishTank feed contains no usable URLs")
            conn.execute("INSERT INTO metadata(fetched_at, entry_count) VALUES (?, ?)", (fetched_at, count))
            conn.commit()
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        return count
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def refresh_feed(force=False):
    """Refresh under a cross-worker lock; keep the last good snapshot on error."""
    if not _enabled():
        return {"state": feed_status()["state"]}
    path = _feed_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_fd = os.open(path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = feed_status()
        if not force and state["state"] == "fresh" and state["ageSeconds"] < REFRESH_INTERVAL_SECONDS:
            return {"state": "fresh"}
        csv_bytes = _download_feed(_app_key())
        count = _write_snapshot(csv_bytes, path, time.time())
        return {"state": "fresh", "entries": count}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


async def refresh_feed_loop():
    while True:
        retry_after = REFRESH_INTERVAL_SECONDS
        try:
            await asyncio.to_thread(refresh_feed)
        except Exception as exc:
            # Never log the feed URL: its path contains the application key.
            print({"warning": "phishtank_refresh_failed", "error": type(exc).__name__})
            retry_after = 15 * 60
        await asyncio.sleep(retry_after)
