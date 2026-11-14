"""Apply owner-reviewed provider identities to a NEW offline SQLite copy.

The source backup is opened read-only and is never modified. This tool cannot
infer an Auth0 connection prefix or verify that an operator's mapping evidence
is genuine; those decisions require review before preparing the JSON input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit


FORMAT = "safescan-identity-mappings-v1"
GOOGLE_ISSUER = "https://accounts.google.com"
PRIVILEGED_ROLES = {"admin", "owner"}
MAPPING_KEYS = {
    "provider", "issuer", "subject", "user_id", "email_at_link", "email_verified",
}
FORBIDDEN_LIVE_ROOTS = (Path("/var/data"), Path("/app/data"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_only(path: Path) -> sqlite3.Connection:
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _auth0_issuer(raw: str | None) -> str | None:
    if not raw:
        return None
    parsed = urlsplit(raw)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Auth0 issuer must be an HTTPS origin.")
    return f"https://{parsed.netloc.lower()}/"


def _check_offline_path(path: Path, *, must_exist: bool) -> Path:
    if path.is_symlink():
        raise ValueError("Symlinked database paths are not allowed.")
    resolved = path.resolve()
    if any(resolved == root or root in resolved.parents for root in FORBIDDEN_LIVE_ROOTS):
        raise ValueError("The production data directory is not an offline backup location.")
    for variable in ("SQLITE_DB_PATH", "DATABASE_URL"):
        configured = os.getenv(variable, "")
        if variable == "DATABASE_URL" and configured.startswith("sqlite:///"):
            configured = configured.removeprefix("sqlite:///")
        if configured and Path(configured).resolve() == resolved:
            raise ValueError("The configured application database is not an offline backup.")
    if must_exist:
        if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("An existing regular SQLite backup is required.")
        if Path(str(path) + "-wal").exists() or Path(str(path) + "-shm").exists():
            raise ValueError("Use a standalone offline backup without WAL sidecars.")
    elif path.exists():
        raise ValueError("The output file must not exist.")
    return resolved


def _approved_plan(path: Path, source_sha256: str) -> list[dict]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("A regular approved-mappings file is required.")
    if path.stat().st_mode & 0o077:
        raise ValueError("Approved mappings must be readable only by the owner (0600).")
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid approved-mappings JSON.") from exc
    if not isinstance(plan, dict) or set(plan) != {"format", "database_sha256", "mappings"}:
        raise ValueError("Invalid approved-mappings structure.")
    if plan["format"] != FORMAT or not re.fullmatch(r"[0-9a-f]{64}", str(plan["database_sha256"])):
        raise ValueError("Invalid approved-mappings version or source hash.")
    if plan["database_sha256"] != source_sha256:
        raise ValueError("Approved mappings do not match this SQLite backup.")
    mappings = plan["mappings"]
    if not isinstance(mappings, list) or not mappings:
        raise ValueError("Approved mappings must be a nonempty list.")
    keys = set()
    for mapping in mappings:
        if not isinstance(mapping, dict) or set(mapping) != MAPPING_KEYS:
            raise ValueError("Invalid identity mapping fields.")
        if mapping["email_verified"] is not True:
            raise ValueError("Identity mapping lacks explicit verified-email proof.")
        for field in ("issuer", "subject", "user_id", "email_at_link"):
            value = mapping[field]
            if (not isinstance(value, str) or not value or value != value.strip() or
                    "\x00" in value or len(value) > 1024):
                raise ValueError("Invalid identity mapping value.")
        if mapping["provider"] not in {"google", "auth0"}:
            raise ValueError("Unsupported identity provider.")
        key = (mapping["issuer"], mapping["subject"])
        if key in keys:
            raise ValueError("Duplicate approved identity mapping.")
        keys.add(key)
    return mappings


def _existing_identity(conn: sqlite3.Connection, issuer: str, subject: str):
    present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_identities'"
    ).fetchone()
    if not present:
        return None
    return conn.execute(
        """SELECT provider, user_id, email_at_link, email_verified
           FROM user_identities WHERE issuer = ? AND subject = ?""",
        (issuer, subject),
    ).fetchone()


def _validate_mappings(conn: sqlite3.Connection, mappings: list[dict],
                       auth0_issuer: str | None, allow_privileged: bool) -> int:
    new_count = 0
    columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if not {"google_id", "email", "role", "status"} <= columns:
        raise ValueError("SQLite backup is missing expected user columns.")
    has_google_sub = "google_sub" in columns
    for mapping in mappings:
        provider = mapping["provider"]
        issuer = mapping["issuer"]
        subject = mapping["subject"]
        if provider == "google":
            if issuer != GOOGLE_ISSUER or "|" in subject:
                raise ValueError("Google mapping has an unexpected issuer or subject.")
        elif issuer != auth0_issuer or not re.fullmatch(r"[^|]+\|.+", subject):
            raise ValueError("Auth0 mapping requires the verified issuer and full subject.")
        user = conn.execute(
            "SELECT google_id, email, role, status" + (", google_sub" if has_google_sub else "") +
            " FROM users WHERE google_id = ?",
            (mapping["user_id"],),
        ).fetchone()
        if user is None or user["status"] != "active":
            raise ValueError("Mapped account is missing or inactive.")
        # The login path lowercases verified token email before comparing it
        # with email_at_link. Store that exact form so a migrated user can log in.
        if (user["email"] or "").strip().lower() != mapping["email_at_link"]:
            raise ValueError("Mapped account email changed since approval.")
        if user["role"] in PRIVILEGED_ROLES and not allow_privileged:
            raise ValueError("Privileged identity mapping requires separate approval flag.")
        if provider == "google" and has_google_sub and user["google_sub"] not in (None, subject):
            raise ValueError("Google subject conflicts with the stored subject.")
        existing = _existing_identity(conn, issuer, subject)
        if existing is None:
            new_count += 1
        elif (existing["provider"] != provider or existing["user_id"] != mapping["user_id"] or
              existing["email_at_link"] != mapping["email_at_link"] or
              existing["email_verified"] != 1):
            raise ValueError("Existing identity mapping conflicts with approval.")
    return new_count


def validate_identity_plan(source: str | Path, approved: str | Path, *,
                           auth0_issuer: str | None = None,
                           allow_privileged: bool = False) -> tuple[list[dict], int, str]:
    source = _check_offline_path(Path(source), must_exist=True)
    source_sha = _sha256(source)
    mappings = _approved_plan(Path(approved), source_sha)
    issuer = _auth0_issuer(auth0_issuer)
    conn = _read_only(source)
    try:
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Source SQLite backup failed integrity check.")
        new_count = _validate_mappings(conn, mappings, issuer, allow_privileged)
    finally:
        conn.close()
    if _sha256(source) != source_sha:
        raise ValueError("SQLite backup changed during validation.")
    return mappings, new_count, source_sha


def prepare_identity_copy(source: str | Path, approved: str | Path, output: str | Path, *,
                          auth0_issuer: str | None = None,
                          allow_privileged: bool = False) -> int:
    """Create and migrate a private copy; never write to the input backup."""
    mappings, new_count, source_sha = validate_identity_plan(
        source, approved, auth0_issuer=auth0_issuer, allow_privileged=allow_privileged,
    )
    source = _check_offline_path(Path(source), must_exist=True)
    output = _check_offline_path(Path(output), must_exist=False)
    if source == output:
        raise ValueError("Input and output paths must differ.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    os.close(descriptor)
    src = None
    dst = None
    try:
        src = _read_only(source)
        dst = sqlite3.connect(str(output))
        dst.row_factory = sqlite3.Row
        src.backup(dst)
        if _sha256(source) != source_sha:
            raise ValueError("SQLite backup changed during copy.")
        dst.execute("PRAGMA foreign_keys=ON")
        with dst:
            dst.execute("BEGIN IMMEDIATE")
            dst.execute('''CREATE TABLE IF NOT EXISTS user_identities (
                provider TEXT NOT NULL CHECK(provider IN ('google', 'auth0')),
                issuer TEXT NOT NULL, subject TEXT NOT NULL,
                user_id TEXT NOT NULL, email_at_link TEXT NOT NULL,
                email_verified INTEGER NOT NULL CHECK(email_verified = 1),
                linked_at TEXT NOT NULL, PRIMARY KEY (issuer, subject),
                FOREIGN KEY(user_id) REFERENCES users(google_id))''')
            dst.execute("CREATE INDEX IF NOT EXISTS idx_user_identities_user_id ON user_identities(user_id)")
            if _validate_mappings(dst, mappings, _auth0_issuer(auth0_issuer), allow_privileged) != new_count:
                raise ValueError("Copied database differs from the approved backup.")
            linked_at = datetime.now(timezone.utc).isoformat()
            for mapping in mappings:
                if _existing_identity(dst, mapping["issuer"], mapping["subject"]) is None:
                    dst.execute(
                        """INSERT INTO user_identities
                           (provider, issuer, subject, user_id, email_at_link, email_verified, linked_at)
                           VALUES (?, ?, ?, ?, ?, 1, ?)""",
                        (mapping["provider"], mapping["issuer"], mapping["subject"],
                         mapping["user_id"], mapping["email_at_link"], linked_at),
                    )
        if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Migrated SQLite copy failed integrity check.")
        return new_count
    except BaseException:
        if dst is not None:
            dst.close()
            dst = None
        output.unlink(missing_ok=True)
        for suffix in ("-journal", "-wal", "-shm"):
            Path(str(output) + suffix).unlink(missing_ok=True)
        raise
    finally:
        if dst is not None:
            dst.close()
        if src is not None:
            src.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True, help="standalone offline SQLite backup")
    parser.add_argument("--approved-mappings", type=Path, required=True, help="0600 owner-reviewed JSON")
    parser.add_argument("--output", type=Path, help="new private migrated DB copy")
    parser.add_argument("--auth0-issuer", help="verified Auth0 tenant issuer")
    parser.add_argument("--allow-privileged", action="store_true", help="owner reviewed admin/owner mappings")
    parser.add_argument("--apply", action="store_true", help="write a NEW copy; never modifies the source")
    args = parser.parse_args(argv)
    try:
        if args.apply:
            if args.output is None:
                raise ValueError("An output path is required for --apply.")
            count = prepare_identity_copy(
                args.database, args.approved_mappings, args.output,
                auth0_issuer=args.auth0_issuer, allow_privileged=args.allow_privileged,
            )
            print(json.dumps({"new_mappings": count, "output_created": True}))
        else:
            _, count, _ = validate_identity_plan(
                args.database, args.approved_mappings,
                auth0_issuer=args.auth0_issuer, allow_privileged=args.allow_privileged,
            )
            print(json.dumps({"new_mappings": count, "output_created": False}))
    except (OSError, sqlite3.Error, ValueError):
        print("Identity application failed; inspect the offline backup and approved mapping file.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
