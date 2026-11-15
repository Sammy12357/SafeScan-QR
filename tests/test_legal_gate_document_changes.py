"""Exercise the diff-aware legal document release guard with changed text."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("legal_document_gate", ROOT / "scripts/check_legal_document_changes.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def _run(monkeypatch, *, old_text="old", new_text="new", old_version="v1.0",
         new_version="v1.0", old_date="May 2026", new_date="May 2026",
         log="", packet=""):
    old = {
        "hackabull/admin_data.py": f'TERMS_HTML = """{old_text}"""',
        "hackabull/config.py": f'LEGAL_VERSION = "{old_version}"\nLEGAL_LAST_UPDATED = "{old_date}"',
    }
    current = {
        "hackabull/admin_data.py": f'TERMS_HTML = """{new_text}"""',
        "hackabull/config.py": f'LEGAL_VERSION = "{new_version}"\nLEGAL_LAST_UPDATED = "{new_date}"',
        "docs/legal/legal-document-changelog.md": log,
        "docs/legal/attorney-packet.md": packet,
        "hackabull/legal_published/terms.v1.0.html": "old",
        f"hackabull/legal_published/terms.{new_version}.html": "new",
        "hackabull/legal_published/privacy.v1.0.html": "old privacy",
        f"hackabull/legal_published/privacy.{new_version}.html": "new privacy",
        "hackabull/legal_published/cookie.v1.0.html": "old cookie",
        f"hackabull/legal_published/cookie.{new_version}.html": "new cookie",
    }
    monkeypatch.setattr(GATE, "_git_show", lambda _base, path: old.get(path))
    monkeypatch.setattr(GATE, "_current", lambda path: current.get(path))
    return GATE.check("a" * 40)


def test_changed_terms_need_new_version_date_and_review_records(monkeypatch):
    errors = _run(monkeypatch)
    assert any("new document version" in item for item in errors)

    errors = _run(monkeypatch, new_version="v1.1", new_date="November 15, 2026")
    assert any("legal-document-changelog" in item for item in errors)
    assert any("attorney-packet" in item for item in errors)

    errors = _run(monkeypatch, new_version="v1.1", new_date="November 15, 2026",
                  log="| terms | v1.1 |\n| privacy | v1.1 |\n| cookie | v1.1 |",
                  packet="Terms, Privacy and Cookie v1.1 need review")
    assert errors == []


def test_unmodified_legal_text_does_not_need_version_bump(monkeypatch):
    assert _run(monkeypatch, old_text="same", new_text="same") == []


def test_cookie_policy_uses_its_own_version_and_requires_snapshots(monkeypatch):
    old = {
        "hackabull/admin_data.py": 'COOKIE_POLICY_HTML = "old"',
        "hackabull/config.py": 'LEGAL_VERSION = "v1.0"\nLEGAL_LAST_UPDATED = "May 2026"',
    }
    current = {
        "hackabull/admin_data.py": 'COOKIE_POLICY_HTML = "new"',
        "hackabull/config.py": 'LEGAL_VERSION = "v1.0"\nLEGAL_LAST_UPDATED = "May 2026"\nCOOKIE_POLICY_VERSION = "v1.1"\nCOOKIE_POLICY_LAST_UPDATED = "November 15, 2026 (proposed)"',
        "docs/legal/legal-document-changelog.md": "| cookie | v1.1 |",
        "docs/legal/attorney-packet.md": "Cookie Policy v1.1 needs review",
    }
    monkeypatch.setattr(GATE, "_git_show", lambda _base, path: old.get(path))
    monkeypatch.setattr(GATE, "_current", lambda path: current.get(path))
    errors = GATE.check("a" * 40)
    assert any("current version has no published snapshot" in error for error in errors)
    assert any("previous version has no published snapshot" in error for error in errors)
    current["hackabull/legal_published/cookie.v1.0.html"] = "old"
    current["hackabull/legal_published/cookie.v1.1.html"] = "new"
    assert GATE.check("a" * 40) == []
