"""Read-only inventory for a future provider-scoped identity migration.

Run this against an offline SQLite backup. It never inserts or updates identities.
Only aggregate counts go to stdout; use --private-report for the review details.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import defaultdict
from contextlib import closing
from pathlib import Path
from urllib.parse import quote, urlsplit


GOOGLE_ISSUER = "https://accounts.google.com"
PRIVILEGED_ROLES = {"admin", "owner"}


def _auth0_issuer(raw: str | None) -> str | None:
    if not raw:
        return None
    parsed = urlsplit(raw)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Auth0 issuer must be an HTTPS origin")
    return f"https://{parsed.netloc.lower()}/"


def _connect_read_only(path: Path) -> sqlite3.Connection:
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _review(items: list[dict], user_id: str | None, reason: str, **context: object) -> None:
    items.append({"user_id": user_id, "reason": reason, **context})


def analyze_database(database: str | Path, *, auth0_issuer: str | None = None) -> dict:
    """Propose unambiguous mappings and report identity conflicts, with no writes.

    A proposed mapping is *not* permission to link accounts by email. This
    inventory cannot recover a full Auth0 subject after legacy prefix stripping.
    """
    issuer = _auth0_issuer(auth0_issuer)
    with closing(_connect_read_only(Path(database))) as conn:
        if not _table_exists(conn, "users"):
            raise ValueError("users table missing")
        user_columns = _columns(conn, "users")
        if not {"google_id", "email"} <= user_columns:
            raise ValueError("users identity columns missing")
        select = ["google_id", "email"]
        for optional in ("google_sub", "role", "status"):
            select.append(optional if optional in user_columns else f"NULL AS {optional}")
        users = [dict(row) for row in conn.execute(f"SELECT {', '.join(select)} FROM users")]

        audit_providers: dict[str, set[str]] = defaultdict(set)
        if _table_exists(conn, "audit_logs"):
            audit_columns = _columns(conn, "audit_logs")
            if {"actor_user_id", "action", "metadata"} <= audit_columns:
                for row in conn.execute(
                    "SELECT actor_user_id, metadata FROM audit_logs WHERE action='user.login'"
                ):
                    try:
                        metadata = json.loads(row["metadata"] or "{}")
                    except (TypeError, ValueError):
                        continue
                    if isinstance(metadata, dict) and isinstance(metadata.get("provider"), str):
                        audit_providers[row["actor_user_id"]].add(metadata["provider"])

        local_by_user: dict[str, set[str]] = defaultdict(set)
        local_by_email: dict[str, set[str]] = defaultdict(set)
        if _table_exists(conn, "local_credentials"):
            if {"email", "user_id"} <= _columns(conn, "local_credentials"):
                for row in conn.execute("SELECT email, user_id FROM local_credentials"):
                    email = (row["email"] or "").strip().casefold()
                    if row["user_id"]:
                        local_by_user[row["user_id"]].add(email)
                    if email:
                        local_by_email[email].add(row["user_id"] or "")

        email_users: dict[str, set[str]] = defaultdict(set)
        sub_users: dict[str, set[str]] = defaultdict(set)
        user_ids = {row["google_id"] for row in users}
        for row in users:
            email = (row["email"] or "").strip().casefold()
            if email and row["status"] != "deleted":
                email_users[email].add(row["google_id"])
            if row["google_sub"]:
                sub_users[row["google_sub"]].add(row["google_id"])

        review: list[dict] = []
        candidates: list[dict] = []
        for row in sorted(users, key=lambda item: item["google_id"] or ""):
            user_id = row["google_id"]
            email = (row["email"] or "").strip().casefold()
            sub = row["google_sub"]
            providers = audit_providers[user_id]
            blockers: set[str] = set()

            if not user_id:
                blockers.add("missing_user_id")
            if not email:
                blockers.add("missing_email")

            if row["status"] and row["status"] != "active":
                blockers.add("inactive_account")
            if email and len(email_users[email]) > 1:
                blockers.add("same_email_multiple_users")
            if user_id in local_by_user or (email and email in local_by_email):
                blockers.add("local_credential_link")
            if user_id in local_by_user and local_by_user[user_id] != {email}:
                blockers.add("local_credential_email_mismatch")
            if sub and sub != user_id:
                blockers.add("google_sub_mismatch")
            if sub and len(sub_users[sub]) > 1:
                blockers.add("shared_google_sub")
            if len(providers & {"auth0_mobile", "google_mobile"}) > 1:
                blockers.add("mixed_provider_history")
            if "auth0_mobile" in providers and "|" not in user_id:
                blockers.add("auth0_subject_lost")
            if row["role"] in PRIVILEGED_ROLES:
                blockers.add("privileged_role")

            # A full legacy Auth0 subject remains in its own issuer namespace.
            # The stripped suffix is never used as an Auth0 subject or a link.
            if "|" in user_id:
                if not issuer:
                    blockers.add("auth0_issuer_required")
                if "google_mobile" in providers or "google_local" in providers:
                    blockers.add("mixed_provider_history")
                if issuer and not blockers:
                    candidates.append({"user_id": user_id, "provider": "auth0",
                                       "issuer": issuer, "subject": user_id})
            elif "google_mobile" in providers:
                if not sub or sub != user_id:
                    blockers.add("google_subject_unconfirmed")
                if not blockers:
                    candidates.append({"user_id": user_id, "provider": "google",
                                       "issuer": GOOGLE_ISSUER, "subject": user_id})
            elif not blockers:
                blockers.add("provider_unconfirmed")

            for reason in sorted(blockers):
                _review(review, user_id, reason, email=email)

        for local_user_id in sorted(local_by_user):
            if local_user_id not in user_ids:
                _review(review, local_user_id, "orphaned_local_credential")

        unrevoked_sessions = 0
        orphaned_sessions = 0
        for table, column in (("sessions", "google_id"), ("persistent_sessions", "user_id")):
            if not _table_exists(conn, table):
                continue
            cols = _columns(conn, table)
            if column not in cols:
                continue
            predicate = " WHERE revoked_at IS NULL" if "revoked_at" in cols else ""
            for row in conn.execute(f"SELECT {column} AS user_id FROM {table}{predicate}"):
                unrevoked_sessions += 1
                if row["user_id"] not in user_ids:
                    orphaned_sessions += 1
                    _review(review, row["user_id"], "orphaned_session", session_table=table)

    accounts_to_review = len({item["user_id"] for item in review if item["user_id"] in user_ids})
    return {
        "summary": {
            "users": len(users),
            "proposed_identities": len(candidates),
            "accounts_requiring_review": accounts_to_review,
            "review_items": len(review),
            "unrevoked_sessions": unrevoked_sessions,
            "orphaned_sessions": orphaned_sessions,
        },
        "candidates": candidates,
        "review": review,
    }


def _write_private_report(path: Path, report: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True, help="offline SQLite backup to inspect")
    parser.add_argument("--auth0-issuer", help="exact Auth0 HTTPS issuer from verified tokens")
    parser.add_argument("--private-report", type=Path, help="new 0600 JSON file for sensitive review details")
    args = parser.parse_args(argv)
    try:
        report = analyze_database(args.database, auth0_issuer=args.auth0_issuer)
        if args.private_report:
            _write_private_report(args.private_report, report)
    except (OSError, sqlite3.Error, ValueError):
        print("Identity inventory failed; check the backup, issuer, and report destination.", file=sys.stderr)
        return 1
    print(json.dumps({"summary": report["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
