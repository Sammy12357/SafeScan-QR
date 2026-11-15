"""Versioned, public metadata for Go Ghost's manual broker directory.

The registry contains links and display guidance only. It is not an
authorization to automate a broker, and it never contains a user's profile.
"""

from __future__ import annotations

from functools import lru_cache
from datetime import date
import json
from pathlib import Path
import re
from urllib.parse import urlparse


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "go_ghost" / "brokers.json"
BROKER_ID = re.compile(r"^[a-z][a-z0-9]*$")
SEARCH_KINDS = {"static"}
REQUIRED_FIELDS = {"id", "name", "priority", "priorityDescription", "removalUrl", "requiredInfo", "group", "lastVerified", "search"}
OPTIONAL_FIELDS = {"operator", "verificationSource", "sourceCheckedAt"}
SEARCH_FIELDS = {"static": {"kind", "url"}}


def _https_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )


@lru_cache(maxsize=1)
def load_brokers() -> tuple[dict, ...]:
    """Read and validate bundled metadata once per worker."""
    records = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    if not isinstance(records, list) or not records:
        raise ValueError("Go Ghost broker registry must be a non-empty list")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Go Ghost broker entry must be an object")
        if not REQUIRED_FIELDS <= record.keys() or record.keys() - REQUIRED_FIELDS - OPTIONAL_FIELDS:
            raise ValueError("Go Ghost broker entry has missing or unknown fields")
        broker_id = record.get("id")
        if not isinstance(broker_id, str) or not BROKER_ID.fullmatch(broker_id) or broker_id in seen:
            raise ValueError("Go Ghost broker ids must be unique lowercase identifiers")
        seen.add(broker_id)
        if not isinstance(record["group"], str) or not BROKER_ID.fullmatch(record["group"]):
            raise ValueError(f"Invalid Go Ghost action group: {broker_id}")
        if not all(isinstance(record.get(key), str) and record[key] for key in ("name", "group", "priority", "priorityDescription")):
            raise ValueError(f"Incomplete Go Ghost broker metadata: {broker_id}")
        if "operator" in record and (not isinstance(record["operator"], str) or not record["operator"]):
            raise ValueError(f"Invalid Go Ghost operator: {broker_id}")
        if not _https_url(record.get("removalUrl")):
            raise ValueError(f"Invalid Go Ghost opt-out URL: {broker_id}")
        if not isinstance(record.get("requiredInfo"), list) or not all(isinstance(item, str) for item in record["requiredInfo"]):
            raise ValueError(f"Invalid Go Ghost required information: {broker_id}")
        for date_field in ("lastVerified", "sourceCheckedAt"):
            if record.get(date_field) is not None:
                try:
                    date.fromisoformat(record[date_field])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Invalid Go Ghost {date_field}: {broker_id}") from exc
        if "verificationSource" in record and not _https_url(record["verificationSource"]):
            raise ValueError(f"Invalid Go Ghost verification source: {broker_id}")
        if record.get("sourceCheckedAt") and "verificationSource" not in record:
            raise ValueError(f"Go Ghost source date needs a source URL: {broker_id}")
        search = record.get("search")
        if not isinstance(search, dict) or search.get("kind") not in SEARCH_KINDS:
            raise ValueError(f"Invalid Go Ghost search mode: {broker_id}")
        if search.keys() != SEARCH_FIELDS[search["kind"]]:
            raise ValueError(f"Invalid Go Ghost search fields: {broker_id}")
        if not _https_url(search.get("url")):
            raise ValueError(f"Invalid Go Ghost static search URL: {broker_id}")
        search_url = urlparse(search["url"])
        if (search_url.hostname != urlparse(record["removalUrl"]).hostname
                or search_url.query or "{" in search["url"] or "}" in search["url"]):
            raise ValueError(f"Go Ghost starting page must use the broker host without a query: {broker_id}")
    return tuple(records)


def broker_metadata(broker_id: str) -> dict | None:
    return next((record for record in load_brokers() if record["id"] == broker_id), None)
