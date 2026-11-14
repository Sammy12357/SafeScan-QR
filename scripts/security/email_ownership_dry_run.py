"""Read-only email and ownership collision inventory for an offline SQLite backup.

Email normalization here identifies records requiring review. It never proves
that two addresses have the same owner, and it never creates identity links.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
import unicodedata
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

import idna


FORMAT = "safescan-email-ownership-audit-v1"
FORBIDDEN_LIVE_ROOTS = (Path("/var/data"), Path("/app/data"))
PRIVILEGED_ROLES = {"admin", "owner"}
SCAN_TABLES = {"scan_history", "scans", "scan_events"}

# These columns contain email strings. The second value distinguishes
# account-owned records from public submissions without a registered user.
EMAIL_FIELDS = {
    "scan_history": (("email",), True),
    "scans": (("email",), True),
    "scan_events": (("email",), True),
    "upload_artifacts": (("email",), True),
    "local_credentials": (("email",), True),
    "alpha_subscriptions": (("email",), True),
    "alpha_solana_payment_references": (("email",), True),
    "go_ghost_removal_jobs": (("email",), True),
    "data_requests": (("email",), False),
    "age_confirmations": (("email",), False),
    "privacy_opt_outs": (("email",), False),
    "waitlist_signups": (("email",), False),
    "waitlist_confirmation_tokens": (("email",), False),
    "abuse_flags": (("email",), False),
    "referrals": (("referrer_email", "referred_email"), False),
    "url_reports": (("reporter_email",), False),
}

OWNED_EMAIL_FIELDS = {
    ("referrals", "referrer_email"),
}

# Newer rows use users.google_id. Older rows in these same columns can contain
# email addresses. Resolve exact known IDs first, then inspect legacy email
# values; never infer an account from a free-form identifier.
MIXED_OWNER_FIELDS = {
    "wallets": ("user_id",),
    "wallet_nonces": ("user_id",),
    "ip_registry": ("user_id",),
    "fraud_flags": ("user_id", "reviewed_by"),
    "scan_velocity": ("user_id",),
    "device_fingerprints": ("user_id",),
    "api_keys": ("created_by",),
    "url_blocklist": ("added_by",),
    "url_reports": ("reviewed_by",),
    "audit_logs": ("target_id",),
}
OPTIONAL_MIXED_FIELDS = {
    ("fraud_flags", "reviewed_by"),
    ("url_reports", "reviewed_by"),
    ("url_blocklist", "added_by"),
}

# These columns hold immutable users.google_id values, not email addresses.
USER_ID_FIELDS = {
    "scan_history": ("user_id",),
    "scans": ("user_id",),
    "scan_events": ("user_id",),
    "upload_artifacts": ("user_id",),
    "local_credentials": ("user_id",),
    "alpha_subscriptions": ("user_id",),
    "alpha_solana_payment_references": ("user_id",),
    "go_ghost_removal_jobs": ("user_id",),
    "alpha_checkout_references": ("user_id",),
    "sessions": ("google_id",),
    "persistent_sessions": ("user_id",),
    "consent_logs": ("user_id",),
    "audit_logs": ("actor_user_id",),
    "discord_links": ("user_id",),
}


def canonical_email(raw: object) -> str | None:
    """Return a *review key* using NFKC/casefold and UTS #46 IDNA.

    This intentionally does not strip plus tags or dots. Quoted local parts
    and malformed addresses remain invalid rather than being guessed at.
    """
    if not isinstance(raw, str) or len(raw) > 1024:
        return None
    value = raw.strip()
    if value.count("@") != 1 or any(char.isspace() or ord(char) < 32 for char in value):
        return None
    local, domain = value.split("@")
    local = unicodedata.normalize("NFKC", local).casefold()
    local = unicodedata.normalize("NFKC", local)
    if not local or not domain or "@" in local or len(local.encode("utf-8")) > 64:
        return None
    if domain.endswith("."):
        domain = domain[:-1]
    try:
        ascii_domain = idna.encode(domain, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return None
    if not ascii_domain or len(ascii_domain) > 253:
        return None
    return f"{local}@{ascii_domain}"


def _mixed_owner(value: object, users: dict[str, dict],
                 email_users: dict[str, set[str]]) -> tuple[str, set[str]]:
    """Classify one mixed-format owner without turning email into an ID."""
    if isinstance(value, str) and value in users:
        return "stable_user_id", {value}
    key = canonical_email(value)
    if key is None:
        if isinstance(value, str) and "@" not in value:
            return "orphaned_user_id", set()
        return "invalid_reference", set()
    candidates = email_users.get(key, set())
    if len(candidates) > 1:
        return "ambiguous_legacy_email", candidates
    if not candidates:
        return "orphaned_legacy_email", set()
    return "unique_legacy_email", candidates


def _offline_path(path: Path) -> Path:
    if os.getenv("RENDER") or os.getenv("ENVIRONMENT", "").strip().lower() in {"prod", "production"}:
        raise ValueError("Run this audit outside the production runtime.")
    if path.is_symlink():
        raise ValueError("Symlinked database paths are not allowed.")
    resolved = path.resolve()
    if any(resolved == root or root in resolved.parents for root in FORBIDDEN_LIVE_ROOTS):
        raise ValueError("The production data directory is not an offline backup.")
    data_dir = os.getenv("DATA_DIR", "").strip()
    if data_dir:
        configured_dir = Path(data_dir).resolve()
        if resolved == configured_dir or configured_dir in resolved.parents:
            raise ValueError("The configured data directory is not an offline backup.")
    for variable in ("SQLITE_DB_PATH", "DATABASE_URL"):
        configured = os.getenv(variable, "")
        if variable == "DATABASE_URL" and configured.startswith("sqlite:///"):
            configured = configured.removeprefix("sqlite:///")
        if configured and Path(configured).resolve() == resolved:
            raise ValueError("The configured application database is not an offline backup.")
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("An existing regular SQLite backup is required.")
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("Use a standalone offline backup without SQLite sidecars.")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    # All table names are hard-coded above; none come from the backup or CLI.
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _rows(conn: sqlite3.Connection, table: str, fields: set[str]):
    columns = ", ".join(sorted(fields))
    yield from conn.execute(f"SELECT rowid AS audit_rowid, {columns} FROM {table}")


def analyze_database(database: str | Path) -> dict:
    """Inventory an immutable offline backup. No account associations are made."""
    path = _offline_path(Path(database))
    source_hash = _sha256(path)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro&immutable=1"
    details: list[dict] = []
    collisions: list[dict] = []
    counts: Counter[str] = Counter()
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        if not _table_exists(conn, "users") or not {"google_id", "email"} <= _columns(conn, "users"):
            raise ValueError("The backup lacks users identity columns.")
        user_cols = _columns(conn, "users")
        user_select = ["rowid AS audit_rowid", "google_id", "email"]
        user_select += [field if field in user_cols else f"NULL AS {field}" for field in ("role", "status")]
        users: dict[str, dict] = {}
        for row in conn.execute(f"SELECT {', '.join(user_select)} FROM users"):
            counts["users"] += 1
            user_id = row["google_id"]
            if not isinstance(user_id, str) or not user_id:
                counts["invalid_user_ids"] += 1
                details.append({"kind": "invalid_user_id", "rowid": row["audit_rowid"]})
            elif user_id in users:
                counts["duplicate_user_ids"] += 1
                details.append({"kind": "duplicate_user_id", "rowid": row["audit_rowid"], "user_id": user_id})
            else:
                users[user_id] = dict(row)
        email_users: dict[str, set[str]] = defaultdict(set)
        for user_id, user in users.items():
            key = canonical_email(user["email"])
            if key is None:
                counts["invalid_user_emails"] += 1
                details.append({"kind": "invalid_user_email", "user_id": user_id, "email": user["email"]})
            else:
                email_users[key].add(user_id)

        identities: dict[str, list[dict]] = defaultdict(list)
        if _table_exists(conn, "user_identities"):
            fields = {"issuer", "subject", "user_id", "email_at_link"}
            if fields <= _columns(conn, "user_identities"):
                for row in conn.execute("SELECT issuer, subject, user_id, email_at_link FROM user_identities"):
                    counts["identities"] += 1
                    identity = {"issuer": row["issuer"], "subject": row["subject"]}
                    identities[row["user_id"]].append(identity)
                    if row["user_id"] not in users:
                        counts["orphaned_identity_links"] += 1
                        details.append({"kind": "orphaned_identity_link", "user_id": row["user_id"], **identity})
                    elif canonical_email(row["email_at_link"]) != canonical_email(users[row["user_id"]]["email"]):
                        counts["stale_identity_email_links"] += 1
                        details.append({"kind": "stale_identity_email_link", "user_id": row["user_id"], **identity,
                                        "email_at_link": row["email_at_link"]})
            else:
                missing_columns.append("user_identities:issuer,subject,user_id,email_at_link")
        else:
            missing_tables.append("user_identities")

        paid_users: set[str] = set()
        wallet_users: set[str] = set()
        wallet_addresses: dict[str, set[str]] = defaultdict(set)
        if _table_exists(conn, "alpha_subscriptions"):
            cols = _columns(conn, "alpha_subscriptions")
            if {"user_id", "status"} <= cols:
                for row in conn.execute("SELECT user_id, status FROM alpha_subscriptions"):
                    if row["status"] == "active" and row["user_id"] in users:
                        paid_users.add(row["user_id"])
        if _table_exists(conn, "wallets"):
            cols = _columns(conn, "wallets")
            if {"user_id", "address", "verified"} <= cols:
                inactive = "AND disconnected_at IS NULL" if "disconnected_at" in cols else ""
                for row in conn.execute(f"SELECT user_id, address FROM wallets WHERE verified=1 {inactive}"):
                    _, possible_owners = _mixed_owner(row["user_id"], users, email_users)
                    for uid in possible_owners:
                        wallet_users.add(uid)
                        wallet_addresses[uid].add(row["address"])
        if _table_exists(conn, "scans") and {"email", "wallet_address"} <= _columns(conn, "scans"):
            for row in conn.execute("SELECT email, wallet_address FROM scans WHERE wallet_address IS NOT NULL AND wallet_address != ''"):
                for uid in email_users.get(canonical_email(row["email"]) or "", ()):
                    wallet_users.add(uid)
                    wallet_addresses[uid].add(row["wallet_address"])

        for key, ids in sorted(email_users.items()):
            if len(ids) < 2:
                continue
            counts["canonical_collision_groups"] += 1
            counts["canonical_collision_users"] += len(ids)
            if any(users[uid]["role"] in PRIVILEGED_ROLES for uid in ids):
                counts["privileged_collision_groups"] += 1
            if ids & paid_users:
                counts["paid_collision_groups"] += 1
            if ids & wallet_users:
                counts["wallet_collision_groups"] += 1
            if len(set().union(*(wallet_addresses[uid] for uid in ids))) > 1:
                counts["multiple_wallet_collision_groups"] += 1
            collisions.append({
                "canonical_email": key,
                "users": [{"user_id": uid, "email": users[uid]["email"],
                           "role": users[uid]["role"], "status": users[uid]["status"],
                           "identities": identities[uid], "paid_active": uid in paid_users,
                           "wallet_evidence": uid in wallet_users} for uid in sorted(ids)],
            })

        all_tables = set(EMAIL_FIELDS) | set(USER_ID_FIELDS) | set(MIXED_OWNER_FIELDS)
        for table in sorted(all_tables):
            if not _table_exists(conn, table):
                missing_tables.append(table)
                continue
            available = _columns(conn, table)
            configured_emails, owned = EMAIL_FIELDS.get(table, ((), True))
            configured_ids = USER_ID_FIELDS.get(table, ())
            configured_mixed = MIXED_OWNER_FIELDS.get(table, ())
            email_fields = tuple(field for field in configured_emails if field in available)
            id_fields = tuple(field for field in configured_ids if field in available)
            mixed_fields = tuple(field for field in configured_mixed if field in available)
            for field in (*configured_emails, *configured_ids, *configured_mixed):
                if field not in available:
                    missing_columns.append(f"{table}:{field}")
            if not email_fields and not id_fields and not mixed_fields:
                continue
            extras = {"target_type"} if table == "audit_logs" and "target_type" in available else set()
            if table == "audit_logs" and not extras:
                missing_columns.append("audit_logs:target_type")
                mixed_fields = tuple(field for field in mixed_fields if field != "target_id")
            if not email_fields and not id_fields and not mixed_fields:
                continue
            for row in _rows(conn, table, set(email_fields + id_fields + mixed_fields) | extras):
                counts["association_rows_examined"] += 1
                row_id = row["audit_rowid"]
                row_issues: set[str] = set()
                row_keys: set[str] = set()
                flagged_emails: dict[str, str] = {}
                for field in email_fields:
                    value = row[field]
                    if value is None or value == "":
                        continue
                    counts["email_references_examined"] += 1
                    key = canonical_email(value)
                    if key is None:
                        counts["invalid_email_references"] += 1
                        row_issues.add("invalid_email_reference")
                        flagged_emails[field] = value
                        continue
                    row_keys.add(key)
                    candidates = email_users.get(key, set())
                    if len(candidates) > 1:
                        counts["ambiguous_email_references"] += 1
                        row_issues.add("ambiguous_email_reference")
                        flagged_emails[field] = value
                    elif not candidates and (owned or (table, field) in OWNED_EMAIL_FIELDS):
                        counts["orphaned_email_references"] += 1
                        row_issues.add("orphaned_email_reference")
                        flagged_emails[field] = value
                for field in id_fields:
                    value = row[field]
                    if value is None or value == "":
                        if row_keys or (table not in {"upload_artifacts", "consent_logs", "audit_logs"}):
                            counts["unbound_user_id_references"] += 1
                            row_issues.add("unbound_user_id_reference")
                            if table in SCAN_TABLES:
                                counts["unbound_scan_rows"] += 1
                        continue
                    counts["user_id_references_examined"] += 1
                    if value not in users:
                        counts["orphaned_user_id_references"] += 1
                        row_issues.add("orphaned_user_id_reference")
                    elif row_keys and canonical_email(users[value]["email"]) not in row_keys:
                        counts["email_user_id_mismatches"] += 1
                        row_issues.add("email_user_id_mismatch")
                for field in mixed_fields:
                    if table == "audit_logs" and row["target_type"] != "user":
                        continue
                    value = row[field]
                    if value is None or value == "":
                        if (table, field) not in OPTIONAL_MIXED_FIELDS:
                            counts["unbound_user_id_references"] += 1
                            row_issues.add("unbound_mixed_owner_reference")
                        continue
                    counts["mixed_owner_references_examined"] += 1
                    kind, _ = _mixed_owner(value, users, email_users)
                    if kind == "stable_user_id":
                        counts["stable_user_id_references"] += 1
                    elif kind == "unique_legacy_email":
                        counts["unique_legacy_email_references"] += 1
                        row_issues.add("legacy_email_owner_reference")
                    elif kind == "ambiguous_legacy_email":
                        counts["ambiguous_email_references"] += 1
                        row_issues.add("ambiguous_legacy_email_reference")
                    elif kind == "orphaned_legacy_email":
                        counts["orphaned_email_references"] += 1
                        row_issues.add("orphaned_legacy_email_reference")
                    elif kind == "orphaned_user_id":
                        counts["orphaned_user_id_references"] += 1
                        row_issues.add("orphaned_user_id_reference")
                    else:
                        counts["invalid_mixed_owner_references"] += 1
                        row_issues.add("invalid_mixed_owner_reference")
                if row_issues:
                    if not flagged_emails:
                        flagged_emails = {field: row[field] for field in email_fields if row[field]}
                    if table in SCAN_TABLES and "ambiguous_email_reference" in row_issues:
                        counts["ambiguous_scan_rows"] += 1
                    counts["association_rows_requiring_review"] += 1
                    details.append({"kind": "association", "table": table, "rowid": row_id,
                                    "issues": sorted(row_issues),
                                    "emails": flagged_emails,
                                    "user_ids": {field: row[field] for field in id_fields if row[field]},
                                    "mixed_references": {field: row[field] for field in mixed_fields if row[field]}})

    if _sha256(path) != source_hash:
        raise ValueError("The offline backup changed during the audit.")
    counts["missing_expected_tables"] = len(missing_tables)
    counts["missing_expected_columns"] = len(missing_columns)
    summary_keys = (
        "users", "invalid_user_ids", "duplicate_user_ids", "identities", "invalid_user_emails",
        "canonical_collision_groups",
        "canonical_collision_users", "privileged_collision_groups", "paid_collision_groups",
        "wallet_collision_groups", "multiple_wallet_collision_groups", "orphaned_identity_links",
        "stale_identity_email_links", "association_rows_examined", "email_references_examined",
        "user_id_references_examined", "mixed_owner_references_examined",
        "stable_user_id_references", "unique_legacy_email_references",
        "invalid_mixed_owner_references", "ambiguous_email_references", "ambiguous_scan_rows",
        "orphaned_email_references", "orphaned_user_id_references", "invalid_email_references",
        "email_user_id_mismatches", "unbound_user_id_references", "unbound_scan_rows",
        "association_rows_requiring_review",
        "missing_expected_tables", "missing_expected_columns",
    )
    return {"format": FORMAT, "database_sha256": source_hash,
            "summary": {key: counts[key] for key in summary_keys},
            "coverage": {"missing_tables": sorted(missing_tables), "missing_columns": sorted(missing_columns)},
            "collisions": collisions, "review": details}


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
    parser.add_argument("--database", type=Path, required=True, help="standalone offline SQLite backup")
    parser.add_argument("--private-report", type=Path, help="new 0600 JSON file for sensitive review details")
    args = parser.parse_args(argv)
    try:
        report = analyze_database(args.database)
        if args.private_report:
            _write_private_report(args.private_report, report)
    except (OSError, sqlite3.Error, ValueError):
        print("Email ownership audit failed; check the offline backup and private report destination.", file=sys.stderr)
        return 1
    print(json.dumps({"summary": report["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
