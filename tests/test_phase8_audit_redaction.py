"""Audit events must not retain scanned URLs or links in free-text metadata."""

import importlib
import json
import sqlite3
import sys


def test_audit_metadata_redacts_url_fields_and_embedded_links(tmp_path, monkeypatch):
    db_path = tmp_path / "audit.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    for name in list(sys.modules):
        if name == "db" or name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    audit = importlib.import_module("hackabull.audit")
    secret_url = "https://private.example/reset?token=topsecret"
    audit.audit_log("test.event", metadata={
        "url": secret_url,
        "nested": {"redirectUrl": secret_url, "message": f"Visited {secret_url} to investigate"},
        "items": ["www.private.example/account", {"link": secret_url}],
        "outcome": "reviewed",
    })
    with sqlite3.connect(db_path) as conn:
        stored = conn.execute("SELECT metadata FROM audit_logs WHERE action = 'test.event'").fetchone()[0]
    data = json.loads(stored)
    assert "url" not in data
    assert "redirectUrl" not in data["nested"]
    assert "link" not in data["items"][1]
    assert data["nested"]["message"] == "Visited [redacted-url] to investigate"
    assert data["items"][0] == "[redacted-url]"
    assert data["outcome"] == "reviewed"
    assert secret_url not in stored
