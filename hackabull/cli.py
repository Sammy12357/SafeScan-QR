"""Explicit, audited maintenance commands for provider-bound accounts."""

from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


GOOGLE_ISSUER = "https://accounts.google.com"


def grant_owner(database: str | Path, google_sub: str, expected_email: str) -> str:
    """Grant owner only to an active account with this verified Google identity.

    Email is a corroborating check, not the account lookup key. The identity
    mapping must already have been created through verified sign-in or reviewed
    migration; this command never manufactures one.
    """
    if not google_sub or google_sub != google_sub.strip() or not expected_email:
        raise ValueError("A Google subject and expected email are required.")
    normalized_email = expected_email.strip().casefold()
    if not normalized_email:
        raise ValueError("An expected email is required.")

    database_uri = "file:" + quote(str(Path(database).resolve()), safe="/") + "?mode=rw"
    conn = sqlite3.connect(database_uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT u.google_id, u.email, u.role, i.email_at_link FROM user_identities AS i
                   JOIN users AS u ON u.google_id = i.user_id
                   WHERE i.provider = 'google' AND i.issuer = ? AND i.subject = ?
                     AND i.email_verified = 1 AND u.status = 'active'""",
                (GOOGLE_ISSUER, google_sub),
            ).fetchone()
            if (
                row is None
                or (row["email"] or "").casefold() != normalized_email
                or (row["email_at_link"] or "").casefold() != normalized_email
            ):
                raise ValueError("Verified Google identity did not match the account.")
            if row["role"] != "owner":
                conn.execute("UPDATE users SET role = 'owner' WHERE google_id = ?", (row["google_id"],))
                conn.execute(
                    """INSERT INTO audit_logs
                       (id, actor_user_id, action, target_type, target_id, metadata,
                        ip_address, user_agent, created_at)
                       VALUES (?, NULL, 'admin.owner_bootstrapped', 'user', ?, ?,
                               NULL, NULL, ?)""",
                    (
                        "audit_" + secrets.token_urlsafe(16),
                        row["google_id"],
                        json.dumps({"method": "verified_google_subject"}),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            return row["google_id"]
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    owner = commands.add_parser("grant-owner", help="grant owner to a reviewed Google identity")
    owner.add_argument("--google-sub", required=True, help="exact Google token subject")
    owner.add_argument("--expected-email", required=True, help="email on the reviewed account")
    owner.add_argument("--database", type=Path, help="SQLite path; defaults to the configured application database")
    owner.add_argument("--apply", action="store_true", help="required to write the role change")
    args = parser.parse_args(argv)
    if not args.apply:
        print("No change made. Add --apply after reviewing the identity mapping.", file=sys.stderr)
        return 2
    try:
        if args.database is None:
            from db import database_path
            args.database = Path(database_path())
        grant_owner(args.database, args.google_sub, args.expected_email)
    except (OSError, sqlite3.Error, ValueError):
        print("Owner bootstrap failed; check the verified identity mapping and database.", file=sys.stderr)
        return 1
    print("Owner role confirmed for the verified Google identity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
